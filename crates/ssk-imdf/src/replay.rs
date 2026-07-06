//! Run descriptor, replay manifest, and reanalysis (IMDF 12).
//!
//! An [`ImdfReplayManifest`] is a compact commitment to *every* input of an
//! observation run — anchor, observer, source, wavefront, verdict — so the run
//! can be re-executed exactly and no input is silently dropped. [`reanalyze`]
//! re-derives the [`SelfAnchor`]'s identity from the recorded fields and
//! confirms it matches the committed id: the anchor is *recovered*, not trusted.

use serde::{Deserialize, Serialize};
use ssk_types::{digest_of, Digest, HashAlg, RunId};

use crate::observer::ObserverId;
use crate::qlogic::QOutcome;
use crate::self_anchor::{SelfAnchor, SelfAnchorId};

/// Everything needed to re-run and reanalyze an observation. Carries its own
/// `run_id` and, when it supersedes an earlier run under anchor-drift, a
/// `prior_trace` back-reference to the committed trace it replaced (Vertrag
/// 8.3). A run is never mutated in place; a drift past bound *forks* a new run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunDescriptor {
    /// Content-derived identity of this run — a function of every input plus the
    /// `prior_trace`, so a fork always yields a distinct id.
    pub run_id: RunId,
    /// The committed trace digest of the run this one superseded, or `None` for
    /// a fresh (non-forked) run.
    pub prior_trace: Option<Digest>,
    pub self_anchor: SelfAnchor,
    pub observer: ObserverId,
    pub source_digest: Digest,
    pub wavefront_digest: Digest,
    pub gate_verdict: String,
}

/// The decision at a run boundary under measured drift: stay in the current run
/// (compensate) or fork a fresh successor (Vertrag 8.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RunTransition {
    /// Drift is within bound — keep observing in the same run.
    Compensate,
    /// Drift exceeded bound — a new run supersedes, back-referencing the old.
    Fork(Box<RunDescriptor>),
}

impl RunDescriptor {
    /// Derive the content-addressed run id from every input plus `prior_trace`.
    fn derive_run_id(
        self_anchor: &SelfAnchor,
        observer: &ObserverId,
        source_digest: &Digest,
        wavefront_digest: &Digest,
        gate_verdict: &str,
        prior_trace: Option<&Digest>,
    ) -> RunId {
        #[derive(Serialize)]
        struct RunIdForm<'a> {
            domain: &'a str,
            self_anchor: &'a SelfAnchorId,
            observer: &'a ObserverId,
            source_digest: &'a Digest,
            wavefront_digest: &'a Digest,
            gate_verdict: &'a str,
            prior_trace: Option<&'a Digest>,
        }
        let d = digest_of(
            &RunIdForm {
                domain: "imdf/run-id/v1",
                self_anchor: &self_anchor.id,
                observer,
                source_digest,
                wavefront_digest,
                gate_verdict,
                prior_trace,
            },
            HashAlg::Blake3,
        )
        .expect("run-id form is serializable");
        RunId::new(d.to_hex())
    }

    #[must_use]
    pub fn new(
        self_anchor: SelfAnchor,
        observer: ObserverId,
        source_digest: Digest,
        wavefront_digest: Digest,
        gate_verdict: QOutcome,
    ) -> Self {
        let verdict = gate_verdict.as_str().to_owned();
        let run_id = Self::derive_run_id(
            &self_anchor,
            &observer,
            &source_digest,
            &wavefront_digest,
            &verdict,
            None,
        );
        RunDescriptor {
            run_id,
            prior_trace: None,
            self_anchor,
            observer,
            source_digest,
            wavefront_digest,
            gate_verdict: verdict,
        }
    }

    /// Fork a successor run that supersedes this one, back-referencing
    /// `superseded_trace` (the committed trace digest of the run being replaced —
    /// e.g. the old [`ImdfReplayManifest::manifest_digest`]). `self` is **not**
    /// mutated; the successor carries a fresh, distinct `run_id` and the same
    /// self-anchor observed under the drifted `source`/`wavefront`/`verdict`.
    #[must_use]
    pub fn fork(
        &self,
        superseded_trace: Digest,
        source_digest: Digest,
        wavefront_digest: Digest,
        gate_verdict: QOutcome,
    ) -> RunDescriptor {
        let verdict = gate_verdict.as_str().to_owned();
        let prior = Some(superseded_trace);
        let run_id = Self::derive_run_id(
            &self.self_anchor,
            &self.observer,
            &source_digest,
            &wavefront_digest,
            &verdict,
            prior.as_ref(),
        );
        RunDescriptor {
            run_id,
            prior_trace: prior,
            self_anchor: self.self_anchor.clone(),
            observer: self.observer,
            source_digest,
            wavefront_digest,
            gate_verdict: verdict,
        }
    }

    /// The Vertrag 8.3 decision: if `drift <= drift_bound` (finite), compensate
    /// in place; otherwise fork a successor superseding `superseded_trace`. A
    /// non-finite drift always forks (fail toward a fresh run).
    #[must_use]
    pub fn advance_under_drift(
        &self,
        drift: f64,
        drift_bound: f64,
        superseded_trace: Digest,
        source_digest: Digest,
        wavefront_digest: Digest,
        gate_verdict: QOutcome,
    ) -> RunTransition {
        if drift.is_finite() && drift <= drift_bound {
            RunTransition::Compensate
        } else {
            RunTransition::Fork(Box::new(self.fork(
                superseded_trace,
                source_digest,
                wavefront_digest,
                gate_verdict,
            )))
        }
    }
}

/// A compact commitment to every input of a run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImdfReplayManifest {
    pub run_id: RunId,
    pub prior_trace: Option<Digest>,
    pub self_anchor_id: SelfAnchorId,
    pub observer: ObserverId,
    pub source_digest: Digest,
    pub wavefront_digest: Digest,
    pub gate_verdict: String,
    pub manifest_digest: Digest,
}

#[derive(Serialize)]
struct ManifestForm<'a> {
    run_id: &'a RunId,
    prior_trace: Option<&'a Digest>,
    self_anchor_id: &'a SelfAnchorId,
    observer: &'a ObserverId,
    source_digest: &'a Digest,
    wavefront_digest: &'a Digest,
    gate_verdict: &'a str,
}

impl ImdfReplayManifest {
    /// Commit a run descriptor, digesting all of its inputs.
    #[must_use]
    pub fn of(descriptor: &RunDescriptor) -> Self {
        let self_anchor_id = descriptor.self_anchor.id;
        let manifest_digest = digest_of(
            &ManifestForm {
                run_id: &descriptor.run_id,
                prior_trace: descriptor.prior_trace.as_ref(),
                self_anchor_id: &self_anchor_id,
                observer: &descriptor.observer,
                source_digest: &descriptor.source_digest,
                wavefront_digest: &descriptor.wavefront_digest,
                gate_verdict: &descriptor.gate_verdict,
            },
            HashAlg::Blake3,
        )
        .expect("manifest form is serializable");
        ImdfReplayManifest {
            run_id: descriptor.run_id.clone(),
            prior_trace: descriptor.prior_trace,
            self_anchor_id,
            observer: descriptor.observer,
            source_digest: descriptor.source_digest,
            wavefront_digest: descriptor.wavefront_digest,
            gate_verdict: descriptor.gate_verdict.clone(),
            manifest_digest,
        }
    }

    /// The committed inputs by name — every input the run depended on.
    #[must_use]
    pub fn committed_inputs(&self) -> Vec<(&'static str, String)> {
        vec![
            ("run_id", self.run_id.0 .0.clone()),
            (
                "prior_trace",
                self.prior_trace.map(|d| d.to_hex()).unwrap_or_default(),
            ),
            ("self_anchor", self.self_anchor_id.0.to_hex()),
            ("observer", self.observer.0.to_hex()),
            ("source", self.source_digest.to_hex()),
            ("wavefront", self.wavefront_digest.to_hex()),
            ("gate_verdict", self.gate_verdict.clone()),
        ]
    }

    /// Recompute the manifest digest from the committed fields — equal to
    /// `manifest_digest` iff no field was altered.
    #[must_use]
    pub fn recompute_digest(&self) -> Digest {
        digest_of(
            &ManifestForm {
                run_id: &self.run_id,
                prior_trace: self.prior_trace.as_ref(),
                self_anchor_id: &self.self_anchor_id,
                observer: &self.observer,
                source_digest: &self.source_digest,
                wavefront_digest: &self.wavefront_digest,
                gate_verdict: &self.gate_verdict,
            },
            HashAlg::Blake3,
        )
        .expect("manifest form is serializable")
    }

    /// Whether the manifest is internally consistent (no field tampered).
    #[must_use]
    pub fn is_consistent(&self) -> bool {
        self.manifest_digest == self.recompute_digest()
    }
}

/// The typed verdict of reanalysis (IMDF, IMRT A8): the class-recovery outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReanalysisVerdict {
    /// The self-class was recovered, the verdict matches, and the manifest is
    /// internally consistent — the run reanalyzes cleanly.
    Pass,
    /// The manifest is consistent but the recovered self-anchor class does not
    /// match the committed one — the identity class drifted (`[S]≠[S_committed]`).
    ClassMismatch,
    /// The manifest is inconsistent or the gate verdict disagrees — reanalysis
    /// cannot decide the class (fail-closed: not a Pass).
    Ambiguous,
}

/// The outcome of reanalyzing a run against its manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReanalysisReport {
    pub self_anchor_recovered: bool,
    pub recovered_anchor: SelfAnchorId,
    pub verdict_matches: bool,
    pub manifest_consistent: bool,
}

impl ReanalysisReport {
    /// Fold the report into a single typed verdict. Fail-closed ordering: an
    /// inconsistent manifest or a disagreeing verdict is `Ambiguous` (the class
    /// cannot be trusted at all); a consistent-but-unrecovered class is a
    /// `ClassMismatch`; only a fully-clean reanalysis is a `Pass`.
    #[must_use]
    pub fn verdict(&self) -> ReanalysisVerdict {
        if !self.manifest_consistent || !self.verdict_matches {
            ReanalysisVerdict::Ambiguous
        } else if !self.self_anchor_recovered {
            ReanalysisVerdict::ClassMismatch
        } else {
            ReanalysisVerdict::Pass
        }
    }
}

/// Re-derive the self-anchor from the descriptor's recorded identity fields and
/// confirm it matches the manifest's committed id (IMDF reanalysis).
#[must_use]
pub fn reanalyze(manifest: &ImdfReplayManifest, descriptor: &RunDescriptor) -> ReanalysisReport {
    let a = &descriptor.self_anchor;
    // Independently recompute the anchor id from its fields — the id must be
    // *derived*, not merely carried.
    let recovered = SelfAnchor::new(
        a.scope.clone(),
        a.owner.clone(),
        a.policy.clone(),
        a.key_context.clone(),
        a.replay_root.clone(),
        a.boundary.clone(),
    );
    ReanalysisReport {
        self_anchor_recovered: recovered.id == manifest.self_anchor_id,
        recovered_anchor: recovered.id,
        verdict_matches: descriptor.gate_verdict == manifest.gate_verdict,
        manifest_consistent: manifest.is_consistent(),
    }
}

/// The Wiederkehrstabilität certificate `w(Φ)` (IMRT A8): a run is *stable on
/// return* iff its replay is deterministic, its reanalysis passes, AND its
/// self-anchor is invariant across the return. `w(Φ)=1` iff all three conjuncts
/// hold; any single failure yields `w(Φ)=0` (fail-closed — an anchor drift
/// forces a new run rather than a silent stable verdict).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StabilityCertificate {
    /// The run re-executes bit-exactly against its manifest.
    pub replay_deterministic: bool,
    /// Reanalysis returned a clean `Pass`.
    pub reanalysis_passed: bool,
    /// The self-anchor class is unchanged across the return.
    pub anchor_invariant: bool,
}

impl StabilityCertificate {
    /// Build the certificate from a replay-determinism bit and a reanalysis
    /// report. `reanalysis_passed` is the typed `Pass` verdict; `anchor_invariant`
    /// is the report's anchor-recovery bit.
    #[must_use]
    pub fn evaluate(replay_deterministic: bool, report: &ReanalysisReport) -> Self {
        StabilityCertificate {
            replay_deterministic,
            reanalysis_passed: report.verdict() == ReanalysisVerdict::Pass,
            anchor_invariant: report.self_anchor_recovered,
        }
    }

    /// The stability weight `w(Φ) ∈ {0,1}` — the conjunction of all three
    /// conjuncts.
    #[must_use]
    pub fn w(&self) -> u8 {
        u8::from(self.replay_deterministic && self.reanalysis_passed && self.anchor_invariant)
    }

    /// Whether the run is stable on return (`w(Φ)=1`).
    #[must_use]
    pub fn is_stable(&self) -> bool {
        self.w() == 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssk_types::{BoundaryRef, KeyContextRef, PolicyId, ReplayRoot};

    fn descriptor() -> RunDescriptor {
        let anchor = SelfAnchor::new(
            "host-a",
            "alice",
            PolicyId::new("p"),
            KeyContextRef::new("k"),
            ReplayRoot::new("r"),
            BoundaryRef::new("b"),
        );
        RunDescriptor::new(
            anchor,
            ObserverId(digest_of(&"obs", HashAlg::Blake3).unwrap()),
            digest_of(&"source", HashAlg::Blake3).unwrap(),
            digest_of(&"wavefront", HashAlg::Blake3).unwrap(),
            QOutcome::Pass,
        )
    }

    // IMDF Appendix A: replay_manifest_contains_all_inputs.
    #[test]
    fn replay_manifest_contains_all_inputs() {
        let d = descriptor();
        let manifest = ImdfReplayManifest::of(&d);
        let names: Vec<&str> = manifest
            .committed_inputs()
            .iter()
            .map(|(n, _)| *n)
            .collect();
        for expected in [
            "self_anchor",
            "observer",
            "source",
            "wavefront",
            "gate_verdict",
        ] {
            assert!(names.contains(&expected), "manifest must commit {expected}");
        }
        assert!(manifest.is_consistent());
        // Dropping/altering any input changes the manifest digest — no silent loss.
        let mut altered = manifest.clone();
        altered.source_digest = digest_of(&"other-source", HashAlg::Blake3).unwrap();
        assert_ne!(altered.recompute_digest(), manifest.manifest_digest);
        assert!(!altered.is_consistent());
    }

    // IMDF Appendix A: reanalysis_recovers_self_anchor.
    #[test]
    fn reanalysis_recovers_self_anchor() {
        let d = descriptor();
        let manifest = ImdfReplayManifest::of(&d);
        let report = reanalyze(&manifest, &d);
        assert!(report.self_anchor_recovered);
        assert_eq!(report.recovered_anchor, d.self_anchor.id);
        assert!(report.verdict_matches);
        assert!(report.manifest_consistent);

        // A manifest committing a different anchor is not recovered.
        let mut wrong = manifest.clone();
        wrong.self_anchor_id = SelfAnchorId(digest_of(&"someone-else", HashAlg::Blake3).unwrap());
        assert!(!reanalyze(&wrong, &d).self_anchor_recovered);
    }

    // G18 (A8): reanalysis yields a typed {Pass, ClassMismatch, Ambiguous}
    // verdict and is class-idempotent — reanalyzing the recovered class again
    // yields the same class (`[Reanalyse∘Reanalyse]_can = [Reanalyse]_can`).
    #[test]
    fn reanalysis_verdict_is_typed_and_class_idempotent() {
        let d = descriptor();
        let manifest = ImdfReplayManifest::of(&d);

        // Clean run → Pass.
        let r1 = reanalyze(&manifest, &d);
        assert_eq!(r1.verdict(), ReanalysisVerdict::Pass);

        // Class-idempotence: reanalysis recovers the canonical self-class; a
        // second reanalysis over that recovered class yields the same class.
        let d2 = RunDescriptor::new(
            d.self_anchor.clone(),
            d.observer,
            d.source_digest,
            d.wavefront_digest,
            QOutcome::Pass,
        );
        let r2 = reanalyze(&ImdfReplayManifest::of(&d2), &d2);
        assert_eq!(
            r2.recovered_anchor, r1.recovered_anchor,
            "[Reanalyse∘Reanalyse]_can == [Reanalyse]_can"
        );
        assert_eq!(r2.verdict(), ReanalysisVerdict::Pass);

        // Consistent manifest, but a committed anchor that does not match the
        // descriptor's recoverable class → ClassMismatch (not Ambiguous).
        let mut mismatched = manifest.clone();
        mismatched.self_anchor_id =
            SelfAnchorId(digest_of(&"other-class", HashAlg::Blake3).unwrap());
        mismatched.manifest_digest = mismatched.recompute_digest(); // keep it consistent
        let rmm = reanalyze(&mismatched, &d);
        assert!(rmm.manifest_consistent && rmm.verdict_matches);
        assert_eq!(rmm.verdict(), ReanalysisVerdict::ClassMismatch);

        // A tampered (inconsistent) manifest → Ambiguous, never a Pass.
        let mut tampered = manifest.clone();
        tampered.source_digest = digest_of(&"tampered", HashAlg::Blake3).unwrap();
        assert!(!tampered.is_consistent());
        assert_eq!(
            reanalyze(&tampered, &d).verdict(),
            ReanalysisVerdict::Ambiguous
        );
    }

    // G2 (Vertrag 8.3): drift past bound forks a new run that back-references the
    // superseded run's committed trace, with a distinct RunId — and the old
    // descriptor is left byte-unchanged (no in-place mutation).
    #[test]
    fn drift_past_bound_forks_a_new_run_without_mutating_the_old() {
        let old = descriptor();
        assert!(old.prior_trace.is_none(), "a fresh run has no prior trace");

        // Snapshot the old descriptor's bytes before any transition.
        let old_bytes = serde_json::to_vec(&old).unwrap();
        let committed_trace = ImdfReplayManifest::of(&old).manifest_digest;

        let drifted_source = digest_of(&"drifted-source", HashAlg::Blake3).unwrap();
        let drifted_wavefront = digest_of(&"drifted-wavefront", HashAlg::Blake3).unwrap();

        // Within bound: compensate — no new run.
        assert_eq!(
            old.advance_under_drift(
                0.1,
                0.5,
                committed_trace,
                drifted_source,
                drifted_wavefront,
                QOutcome::Pass
            ),
            RunTransition::Compensate
        );

        // Past bound: fork.
        let transition = old.advance_under_drift(
            0.9,
            0.5,
            committed_trace,
            drifted_source,
            drifted_wavefront,
            QOutcome::Hold,
        );
        let RunTransition::Fork(new) = transition else {
            panic!("drift past bound must fork a new run");
        };

        // Distinct RunId.
        assert_ne!(new.run_id, old.run_id, "a fork must have a distinct run id");
        // Back-reference equals the old run's committed trace digest.
        assert_eq!(
            new.prior_trace,
            Some(committed_trace),
            "the successor back-references the superseded committed trace"
        );
        // Same self-anchor, drifted measurement.
        assert_eq!(new.self_anchor, old.self_anchor);
        assert_eq!(new.source_digest, drifted_source);
        // A non-finite drift always forks.
        assert!(matches!(
            old.advance_under_drift(
                f64::NAN,
                0.5,
                committed_trace,
                drifted_source,
                drifted_wavefront,
                QOutcome::Pass
            ),
            RunTransition::Fork(_)
        ));

        // The old descriptor is byte-unchanged — no in-place mutation.
        assert_eq!(
            serde_json::to_vec(&old).unwrap(),
            old_bytes,
            "forking must not mutate the superseded run"
        );

        // The fork's prior_trace is committed in its manifest (no silent loss).
        let new_manifest = ImdfReplayManifest::of(&new);
        let names: Vec<&str> = new_manifest
            .committed_inputs()
            .iter()
            .map(|(n, _)| *n)
            .collect();
        assert!(names.contains(&"run_id"));
        assert!(names.contains(&"prior_trace"));
        assert!(new_manifest.is_consistent());
    }

    // G17 (A8): w(Φ)=1 iff replay-determinism ∧ reanalysis-Pass ∧
    // anchor-invariance all hold; any single failed conjunct yields w(Φ)=0.
    // Enumerate all 2^3 combinations.
    #[test]
    fn stability_certificate_is_the_conjunction_of_three_conjuncts() {
        for replay in [false, true] {
            for reanalysis in [false, true] {
                for anchor in [false, true] {
                    // Synthesize a report with the desired reanalysis/anchor bits.
                    let report = ReanalysisReport {
                        self_anchor_recovered: anchor,
                        recovered_anchor: SelfAnchorId(digest_of(&"c", HashAlg::Blake3).unwrap()),
                        // A Pass verdict needs manifest_consistent && verdict_matches
                        // && self_anchor_recovered; drive the first two together.
                        verdict_matches: reanalysis,
                        manifest_consistent: reanalysis,
                    };
                    let reanalysis_passed = report.verdict() == ReanalysisVerdict::Pass;
                    let cert = StabilityCertificate::evaluate(replay, &report);
                    assert_eq!(cert.reanalysis_passed, reanalysis_passed);
                    let expected = u8::from(replay && reanalysis_passed && anchor);
                    assert_eq!(
                        cert.w(),
                        expected,
                        "w(Φ) is the conjunction (replay={replay}, reanalysis={reanalysis}, anchor={anchor})"
                    );
                    assert_eq!(cert.is_stable(), expected == 1);
                }
            }
        }

        // The fully-clean run is stable; a real anchor drift breaks it.
        let d = descriptor();
        let manifest = ImdfReplayManifest::of(&d);
        let clean = StabilityCertificate::evaluate(true, &reanalyze(&manifest, &d));
        assert!(clean.is_stable(), "a clean, deterministic run is stable");

        let mut drifted = manifest.clone();
        drifted.self_anchor_id = SelfAnchorId(digest_of(&"drifted", HashAlg::Blake3).unwrap());
        drifted.manifest_digest = drifted.recompute_digest();
        let unstable = StabilityCertificate::evaluate(true, &reanalyze(&drifted, &d));
        assert!(
            !unstable.is_stable(),
            "an anchor drift breaks stability even with deterministic replay"
        );
    }
}
