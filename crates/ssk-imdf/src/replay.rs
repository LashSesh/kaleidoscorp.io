//! Run descriptor, replay manifest, and reanalysis (IMDF 12).
//!
//! An [`ImdfReplayManifest`] is a compact commitment to *every* input of an
//! observation run — anchor, observer, source, wavefront, verdict — so the run
//! can be re-executed exactly and no input is silently dropped. [`reanalyze`]
//! re-derives the [`SelfAnchor`]'s identity from the recorded fields and
//! confirms it matches the committed id: the anchor is *recovered*, not trusted.

use serde::{Deserialize, Serialize};
use ssk_types::{digest_of, Digest, HashAlg};

use crate::observer::ObserverId;
use crate::qlogic::QOutcome;
use crate::self_anchor::{SelfAnchor, SelfAnchorId};

/// Everything needed to re-run and reanalyze an observation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunDescriptor {
    pub self_anchor: SelfAnchor,
    pub observer: ObserverId,
    pub source_digest: Digest,
    pub wavefront_digest: Digest,
    pub gate_verdict: String,
}

impl RunDescriptor {
    #[must_use]
    pub fn new(
        self_anchor: SelfAnchor,
        observer: ObserverId,
        source_digest: Digest,
        wavefront_digest: Digest,
        gate_verdict: QOutcome,
    ) -> Self {
        RunDescriptor {
            self_anchor,
            observer,
            source_digest,
            wavefront_digest,
            gate_verdict: gate_verdict.as_str().to_owned(),
        }
    }
}

/// A compact commitment to every input of a run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImdfReplayManifest {
    pub self_anchor_id: SelfAnchorId,
    pub observer: ObserverId,
    pub source_digest: Digest,
    pub wavefront_digest: Digest,
    pub gate_verdict: String,
    pub manifest_digest: Digest,
}

#[derive(Serialize)]
struct ManifestForm<'a> {
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

/// The outcome of reanalyzing a run against its manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReanalysisReport {
    pub self_anchor_recovered: bool,
    pub recovered_anchor: SelfAnchorId,
    pub verdict_matches: bool,
    pub manifest_consistent: bool,
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
}
