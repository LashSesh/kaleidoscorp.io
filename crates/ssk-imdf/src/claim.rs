//! Claim 8-tuple + weight-gating (IMDF; IMRT Axiom A5, Satz 14.5).
//!
//! An observer yields a **Befund** (finding), never Wahrheit. A [`Claim`] is the
//! typed carrier of one finding: an 8-tuple
//! `(subject, predicate, scope, layer, ground, status, residue, trace)`. It
//! carries **weight** (`weight(c)=1`) iff, per Satz 14.5:
//!
//! * its `ground` is non-empty (`Ground≠∅`),
//! * its gate `status` is defined (`Gate defined`) and in `{Pass,Hold,Fail}`,
//! * and its `residue` is *declared* (even if "no residue").
//!
//! A weight-0 claim is not truth-apt: `Ground=∅` makes it an **Entwurf** (draft),
//! an undefined gate makes it a **Hypothese** (hypothesis), and an undeclared
//! residue leaves it unconserved. The append-only ledger Λ ([`ClaimLedger`])
//! **refuses** to write any claim that does not carry full weight.

use serde::{Deserialize, Serialize};
use ssk_types::{ResidueId, TraceId};

use crate::qlogic::QOutcome;

/// The residue disposition of a claim (A4 applied to A5): a claim must *declare*
/// its residue — even declaring "none" is a declaration. An `Undeclared`
/// residue is an A4 violation that costs the claim its weight.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResidueDisposition {
    /// No residue statement was made — an A4 violation (weight 0).
    Undeclared,
    /// Declared: this claim leaves no residue.
    DeclaredNone,
    /// Declared: this claim produced the named residue.
    Declared(ResidueId),
}

impl ResidueDisposition {
    /// Whether a residue statement was made (either "none" or a concrete id).
    #[must_use]
    pub fn is_declared(&self) -> bool {
        !matches!(self, ResidueDisposition::Undeclared)
    }
}

/// Why a claim carries no weight — the defect class it falls into (Satz 14.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaimClass {
    /// Fully-formed: `weight(c)=1`, eligible for Λ.
    WellFormed,
    /// `Ground=∅` — a draft finding with no evidential ground.
    Entwurf,
    /// The gate is undefined — a hypothesis, not yet gate-qualified.
    Hypothese,
    /// The residue was not declared — the finding is unconserved (A4).
    ResidueUndeclared,
}

/// A finding (Befund), never a truth: the typed 8-tuple carrier of A5.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claim {
    pub subject: String,
    pub predicate: String,
    pub scope: String,
    pub layer: String,
    /// The evidential grounds. Empty ⇒ `Entwurf` (no ground).
    pub ground: Vec<String>,
    /// The gate status. `None` ⇒ gate undefined ⇒ `Hypothese`.
    pub status: Option<QOutcome>,
    /// The declared residue disposition (A4).
    pub residue: ResidueDisposition,
    pub trace: TraceId,
}

impl Claim {
    /// The defect class of the claim (Satz 14.5), checked in the theory's order:
    /// ground, then gate, then residue.
    #[must_use]
    pub fn classify(&self) -> ClaimClass {
        if self.ground.is_empty() {
            ClaimClass::Entwurf
        } else if self.status.is_none() {
            ClaimClass::Hypothese
        } else if !self.residue.is_declared() {
            ClaimClass::ResidueUndeclared
        } else {
            ClaimClass::WellFormed
        }
    }

    /// The Satz 14.5 weight: `1` iff `Ground≠∅ ∧ Gate defined ∧
    /// Status∈{Pass,Hold,Fail} ∧ Residue declared`, else `0`. (`QOutcome` is by
    /// construction exactly `{Pass,Hold,Fail}`, so a defined status is always in
    /// the codomain.)
    #[must_use]
    pub fn weight(&self) -> u8 {
        u8::from(self.classify() == ClaimClass::WellFormed)
    }

    /// Whether the claim is truth-apt (carries full weight) and may be written
    /// to Λ.
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        self.weight() == 1
    }
}

/// Rejection reason when Λ refuses a claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ClaimError {
    #[error("claim carries no weight ({0:?}); refused append to Λ")]
    Underweight(ClaimClass),
}

/// The append-only claim ledger Λ. It **only** accepts weight-1 claims —
/// Entwürfe and Hypothesen never reach it (Satz 14.5). There is no removal API.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ClaimLedger {
    entries: Vec<Claim>,
}

impl ClaimLedger {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a claim to Λ. Fails closed with the claim's defect class if it
    /// does not carry full weight.
    ///
    /// # Errors
    /// [`ClaimError::Underweight`] if `weight(c) != 1`.
    pub fn append(&mut self, claim: Claim) -> Result<(), ClaimError> {
        let class = claim.classify();
        if class == ClaimClass::WellFormed {
            self.entries.push(claim);
            Ok(())
        } else {
            Err(ClaimError::Underweight(class))
        }
    }

    #[must_use]
    pub fn entries(&self) -> &[Claim] {
        &self.entries
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn well_formed() -> Claim {
        Claim {
            subject: "surface:trace-1".to_owned(),
            predicate: "is-canonical".to_owned(),
            scope: "self".to_owned(),
            layer: "L5".to_owned(),
            ground: vec!["wavefront:abc".to_owned()],
            status: Some(QOutcome::Pass),
            residue: ResidueDisposition::DeclaredNone,
            trace: TraceId::new("t1"),
        }
    }

    // G24 (Satz 14.5): a well-formed claim has weight 1 and is written to Λ.
    #[test]
    fn well_formed_claim_has_weight_one_and_is_written() {
        let mut lambda = ClaimLedger::new();
        let c = well_formed();
        assert_eq!(c.weight(), 1);
        assert_eq!(c.classify(), ClaimClass::WellFormed);
        assert!(lambda.append(c).is_ok());
        assert_eq!(lambda.len(), 1);
    }

    // G24 (Satz 14.5): Ground=∅ → weight 0, classified Entwurf, refused.
    #[test]
    fn groundless_claim_is_entwurf_and_refused() {
        let mut lambda = ClaimLedger::new();
        let c = Claim {
            ground: vec![],
            ..well_formed()
        };
        assert_eq!(c.weight(), 0);
        assert_eq!(c.classify(), ClaimClass::Entwurf);
        assert_eq!(
            lambda.append(c).unwrap_err(),
            ClaimError::Underweight(ClaimClass::Entwurf)
        );
        assert!(lambda.is_empty(), "an Entwurf never reaches Λ");
    }

    // G24 (Satz 14.5): an undefined gate → weight 0, classified Hypothese.
    #[test]
    fn gate_undefined_claim_is_hypothese_and_refused() {
        let mut lambda = ClaimLedger::new();
        let c = Claim {
            status: None,
            ..well_formed()
        };
        assert_eq!(c.weight(), 0);
        assert_eq!(c.classify(), ClaimClass::Hypothese);
        assert_eq!(
            lambda.append(c).unwrap_err(),
            ClaimError::Underweight(ClaimClass::Hypothese)
        );
        assert!(lambda.is_empty(), "a Hypothese never reaches Λ");
    }

    // G24 (A4 within A5): an undeclared residue costs the claim its weight.
    #[test]
    fn undeclared_residue_claim_is_refused() {
        let mut lambda = ClaimLedger::new();
        let c = Claim {
            residue: ResidueDisposition::Undeclared,
            ..well_formed()
        };
        assert_eq!(c.weight(), 0);
        assert_eq!(c.classify(), ClaimClass::ResidueUndeclared);
        assert!(lambda.append(c).is_err());

        // A declared concrete residue is fine.
        let with_res = Claim {
            residue: ResidueDisposition::Declared(ResidueId::new("r1")),
            ..well_formed()
        };
        assert_eq!(with_res.weight(), 1);
    }

    // Every QOutcome status is in the Satz 14.5 codomain {Pass,Hold,Fail}.
    #[test]
    fn any_defined_gate_status_qualifies() {
        for status in [QOutcome::Pass, QOutcome::Hold, QOutcome::Fail] {
            let c = Claim {
                status: Some(status),
                ..well_formed()
            };
            assert_eq!(c.weight(), 1, "a Fail is still a defined, weighted finding");
        }
    }
}
