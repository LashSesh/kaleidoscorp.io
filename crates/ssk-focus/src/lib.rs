#![forbid(unsafe_code)]

use ssk_crypto::HashProvider;
use ssk_privacy::{HeuristicLinkabilityEstimator, LinkabilityEstimator, LinkabilityReport};
use ssk_privacy::{ObservedSurface, SurfaceComponent, ThreatCtx};
use ssk_types::{
    CoreId, CoreNode, Digest, FacetId, FiberType, LocatorId, ReplayReportRef, ResidueId, TraceId,
};
use std::collections::BTreeMap;

/// Real backing check for `ssk-gates::FocusGate` — kept unchanged: a fast,
/// structural gate-time check ("does this candidate's facet already belong
/// to its own core") distinct from `FocusEngine::reanalyze`'s heavier,
/// response-evidence-based session reconstruction below.
#[must_use]
pub fn refocuses(candidate: &ssk_types::StitchCandidate) -> bool {
    candidate.focus_ready && candidate.facet.core == candidate.core.id
}

/// One captured response used as reanalysis evidence (Master Spec Ω+1
/// ch. 13.1, verbatim field list) — the payload itself is never stored,
/// only its digest.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Response {
    pub facet: FacetId,
    pub locator: LocatorId,
    pub fiber: FiberType,
    pub trace: TraceId,
    pub payload_digest: Digest,
}

/// The reconstructed internal session class (ch. 13.1's referenced but
/// unenumerated `CoreSessionClass`) — this document's own minimal,
/// disclosed elaboration: either responses reconstruct cleanly to one core,
/// or they don't.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum CoreSessionClass {
    Reconstructed(CoreId),
    Unknown,
}

/// Ch. 13.1, verbatim variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum FocusVerdict {
    Pass,
    ClassMismatch,
    Ambiguous,
}

/// Ch. 13.1, verbatim field list.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct FocusReport {
    pub reconstructed: CoreSessionClass,
    pub residues: Vec<ResidueId>,
    pub replay: ReplayReportRef,
    pub linkability: LinkabilityReport,
    pub verdict: FocusVerdict,
}

/// Phase 5 placeholder for the real `ssk-config::Policy` collaborator, same
/// disclosed pattern as `ssk_core::connection::Policy`/`ssk_gates::Policy`.
#[derive(Debug, Clone, Copy, Default)]
pub struct Policy;

/// Ch. 13.1, verbatim shape.
pub struct FocusEngine<'p> {
    provider: &'p dyn HashProvider,
}

impl<'p> FocusEngine<'p> {
    #[must_use]
    pub fn new(provider: &'p dyn HashProvider) -> Self {
        Self { provider }
    }

    /// Reconstructs an internal session class from response evidence
    /// (ch. 13.1's invariant — "does not prove payload truth, endpoint
    /// trustworthiness, or absence of observation"). Real, bounded checks
    /// only: a session reconstructs cleanly when every response shares one
    /// facet and the core itself is canonically signed; a facet directory
    /// linking arbitrary facets back to a core does not exist in this
    /// codebase, so cross-facet reconstruction is honestly reported as
    /// `ClassMismatch` rather than guessed at.
    #[must_use]
    pub fn reanalyze(&self, responses: &[Response], core: &CoreNode, _p: &Policy) -> FocusReport {
        let (reconstructed, verdict) = if responses.is_empty() {
            (CoreSessionClass::Unknown, FocusVerdict::Ambiguous)
        } else {
            let distinct_facets: std::collections::HashSet<_> =
                responses.iter().map(|r| &r.facet).collect();
            if distinct_facets.len() > 1 || !core.signature.is_present() {
                (CoreSessionClass::Unknown, FocusVerdict::ClassMismatch)
            } else {
                (
                    CoreSessionClass::Reconstructed(core.id.clone()),
                    FocusVerdict::Pass,
                )
            }
        };

        let residues = if matches!(verdict, FocusVerdict::Pass) {
            Vec::new()
        } else {
            vec![ResidueId::new(format!("focus-residue:{}", core.id.0 .0))]
        };

        let linkability = self.linkability_report(responses);
        let replay = self.replay_report_ref(responses, core);

        FocusReport {
            reconstructed,
            residues,
            replay,
            linkability,
            verdict,
        }
    }

    /// Locator reuse across a session's responses is the observable
    /// correlation signal available at this layer (a `Response` carries no
    /// independent risk score of its own) — a locator seen `n` times
    /// contributes `20 * (n - 1)` risk, capped at 100. A `BTreeMap` (not
    /// `HashMap`) is used deliberately: its iteration order is the sorted key
    /// order, so the resulting `components` list — and therefore the whole
    /// `FocusReport`, which is `Serialize` + `PartialEq` and embedded in a
    /// replay-compared `RunOutcome` — is a deterministic function of the
    /// input, not of a per-process `HashMap` random seed.
    fn linkability_report(&self, responses: &[Response]) -> LinkabilityReport {
        let mut counts: BTreeMap<LocatorId, u32> = BTreeMap::new();
        for r in responses {
            *counts.entry(r.locator.clone()).or_insert(0) += 1;
        }
        let components: Vec<SurfaceComponent> = counts
            .into_iter()
            .map(|(locator, count)| SurfaceComponent {
                locator,
                risk_score: u8::try_from(count.saturating_sub(1).saturating_mul(20).min(100))
                    .unwrap_or(100),
            })
            .collect();
        let obs = ObservedSurface { components };
        HeuristicLinkabilityEstimator.report(&obs, &ThreatCtx)
    }

    /// Content-addresses the session's response digests via the real
    /// `HashProvider` this engine holds — no replay-report registry exists
    /// yet to look up, so this stands in as a deterministic reference until
    /// one lands.
    fn replay_report_ref(&self, responses: &[Response], core: &CoreNode) -> ReplayReportRef {
        if responses.is_empty() {
            return ReplayReportRef::new(format!("focus-replay:{}:empty", core.id.0 .0));
        }
        let bytes: Vec<u8> = responses.iter().flat_map(|r| r.payload_digest.0).collect();
        let raw = self.provider.digest(&bytes);
        let mut arr = [0u8; 32];
        let len = raw.len().min(32);
        arr[..len].copy_from_slice(&raw[..len]);
        ReplayReportRef::new(Digest(arr).to_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssk_crypto::Blake3HashProvider;
    use ssk_types::{
        AuditRoot, CanonicalForm, ClosureState, CoreSignature, HashAlg, PolicyId, ReplayRoot,
    };

    fn core() -> CoreNode {
        CoreNode {
            id: CoreId::new("c1"),
            canonical: CanonicalForm("n".into()),
            signature: CoreSignature(vec![1, 2, 3]),
            policy_root: PolicyId::new("p1"),
            replay_root: ReplayRoot::new("rr"),
            audit_root: AuditRoot::new("ar"),
            closure: ClosureState::Closed,
        }
    }

    fn response(facet: &str, locator: &str) -> Response {
        Response {
            facet: FacetId::of(&facet, HashAlg::Blake3).expect("hash"),
            locator: LocatorId::new(locator),
            fiber: FiberType::Data,
            trace: TraceId::new("trace"),
            payload_digest: Digest::GENESIS,
        }
    }

    #[test]
    fn empty_responses_are_ambiguous() {
        let provider = Blake3HashProvider;
        let engine = FocusEngine::new(&provider);
        let report = engine.reanalyze(&[], &core(), &Policy);
        assert_eq!(report.verdict, FocusVerdict::Ambiguous);
        assert_eq!(report.reconstructed, CoreSessionClass::Unknown);
    }

    #[test]
    fn single_facet_responses_reconstruct_cleanly() {
        let provider = Blake3HashProvider;
        let engine = FocusEngine::new(&provider);
        let responses = vec![response("f1", "l1"), response("f1", "l1")];
        let report = engine.reanalyze(&responses, &core(), &Policy);
        assert_eq!(report.verdict, FocusVerdict::Pass);
        assert_eq!(
            report.reconstructed,
            CoreSessionClass::Reconstructed(CoreId::new("c1"))
        );
        // l1 was reused (seen twice) -> non-zero linkability risk.
        assert!(report.linkability.score.0 > 0.0);
    }

    #[test]
    fn mixed_facet_responses_are_a_class_mismatch() {
        let provider = Blake3HashProvider;
        let engine = FocusEngine::new(&provider);
        let responses = vec![response("f1", "l1"), response("f2", "l1")];
        let report = engine.reanalyze(&responses, &core(), &Policy);
        assert_eq!(report.verdict, FocusVerdict::ClassMismatch);
        assert!(!report.residues.is_empty());
    }

    // Regression: the linkability report's component order must be a
    // deterministic function of the input, not of a HashMap's per-instance
    // random seed. Several distinct, equally-reused locators make the
    // nondeterminism observable if `counts` were ever a HashMap again — with
    // enough distinct keys, two independently-built maps are near-certain to
    // iterate in different orders.
    #[test]
    fn linkability_component_order_is_deterministic() {
        let provider = Blake3HashProvider;
        let engine = FocusEngine::new(&provider);
        // Each of 5 distinct locators reused 5x: risk_score = 20*(5-1) = 80,
        // clearing the >70 high-risk threshold, so all five show up in
        // high_risk_components and their order is observable.
        let locators = ["l_a", "l_b", "l_c", "l_d", "l_e"];
        let responses: Vec<Response> = locators
            .iter()
            .flat_map(|loc| std::iter::repeat_n(response("f1", loc), 5))
            .collect();

        let a = engine.reanalyze(&responses, &core(), &Policy);
        let b = engine.reanalyze(&responses, &core(), &Policy);

        assert_eq!(
            a.linkability, b.linkability,
            "identical input must produce an identical (order-stable) linkability report"
        );
        assert_eq!(
            serde_json::to_string(&a).unwrap(),
            serde_json::to_string(&b).unwrap(),
            "identical input must serialize identically across independent runs (replay)"
        );
        // Every locator was reused equally (2x), so all five are high-risk;
        // their order must be the sorted LocatorId order, not insertion order.
        assert_eq!(a.linkability.high_risk_components.len(), 5);
        let ids: Vec<_> = a
            .linkability
            .high_risk_components
            .iter()
            .map(|c| c.locator.0 .0.clone())
            .collect();
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(ids, sorted, "components must be in sorted LocatorId order");
    }
}
