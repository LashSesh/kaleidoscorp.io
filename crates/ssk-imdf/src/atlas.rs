//! The `SelfPerceptionAtlas` (IMDF 13) — the Mirror Dome's main artifact.
//!
//! An append-only, hash-chained record of what the system has perceived about
//! itself. Each entry commits to the prior entry's hash, so the chain is
//! tamper-evident: altering any past observation without recomputing the whole
//! tail breaks [`SelfPerceptionAtlas::verify_chain`]. There is no API to edit or
//! remove an entry — only to append.

use serde::{Deserialize, Serialize};
use ssk_types::{digest_of, Digest, HashAlg};

use crate::observer::ObserverId;
use crate::self_anchor::SelfAnchorId;

/// One perceived observation committed to the atlas.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtlasObservation {
    pub self_anchor: SelfAnchorId,
    pub observer: ObserverId,
    pub source_digest: Digest,
    pub wavefront_digest: Digest,
    pub gate_verdict: String,
}

/// A chained atlas entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtlasEntry {
    pub seq: u64,
    pub prev_hash: Digest,
    pub observation: AtlasObservation,
    pub entry_hash: Digest,
}

#[derive(Serialize)]
struct EntryForm<'a> {
    seq: u64,
    prev_hash: &'a Digest,
    observation: &'a AtlasObservation,
}

fn compute_entry_hash(seq: u64, prev_hash: &Digest, observation: &AtlasObservation) -> Digest {
    digest_of(
        &EntryForm {
            seq,
            prev_hash,
            observation,
        },
        HashAlg::Blake3,
    )
    .expect("atlas entry is serializable")
}

/// The append-only, hash-chained self-perception atlas.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelfPerceptionAtlas {
    entries: Vec<AtlasEntry>,
}

impl SelfPerceptionAtlas {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The current chain head (last entry hash, or genesis for an empty atlas).
    #[must_use]
    pub fn head(&self) -> Digest {
        self.entries
            .last()
            .map_or(Digest::GENESIS, |e| e.entry_hash)
    }

    /// Append an observation, chaining it to the current head. Returns the new
    /// entry's hash. There is no counterpart to remove or edit — append only.
    pub fn append(&mut self, observation: AtlasObservation) -> Digest {
        let seq = self.entries.len() as u64;
        let prev_hash = self.head();
        let entry_hash = compute_entry_hash(seq, &prev_hash, &observation);
        self.entries.push(AtlasEntry {
            seq,
            prev_hash,
            observation,
            entry_hash,
        });
        entry_hash
    }

    #[must_use]
    pub fn entries(&self) -> &[AtlasEntry] {
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

    /// Verify the whole chain: each entry's `entry_hash` recomputes, and its
    /// `prev_hash` links to the prior entry (genesis for the first).
    #[must_use]
    pub fn verify_chain(&self) -> bool {
        let mut expected_prev = Digest::GENESIS;
        for (index, entry) in self.entries.iter().enumerate() {
            if entry.seq != index as u64 {
                return false;
            }
            if entry.prev_hash != expected_prev {
                return false;
            }
            if entry.entry_hash
                != compute_entry_hash(entry.seq, &entry.prev_hash, &entry.observation)
            {
                return false;
            }
            expected_prev = entry.entry_hash;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation(tag: &str, verdict: &str) -> AtlasObservation {
        AtlasObservation {
            self_anchor: SelfAnchorId(
                digest_of(&format!("anchor-{tag}"), HashAlg::Blake3).unwrap(),
            ),
            observer: ObserverId(digest_of(&format!("obs-{tag}"), HashAlg::Blake3).unwrap()),
            source_digest: digest_of(&format!("src-{tag}"), HashAlg::Blake3).unwrap(),
            wavefront_digest: digest_of(&format!("wf-{tag}"), HashAlg::Blake3).unwrap(),
            gate_verdict: verdict.to_owned(),
        }
    }

    // IMDF Appendix A: audit_ledger_is_append_only.
    #[test]
    fn audit_ledger_is_append_only() {
        let mut atlas = SelfPerceptionAtlas::new();
        assert!(atlas.is_empty());
        assert_eq!(atlas.head(), Digest::GENESIS);

        let h0 = atlas.append(observation("a", "PASS"));
        let h1 = atlas.append(observation("b", "HOLD"));
        let h2 = atlas.append(observation("c", "PASS"));
        assert_eq!(atlas.len(), 3);
        // Head advances with every append; entries chain forward.
        assert_ne!(h0, h1);
        assert_ne!(h1, h2);
        assert_eq!(atlas.head(), h2);
        assert_eq!(atlas.entries()[1].prev_hash, h0);
        assert_eq!(atlas.entries()[2].prev_hash, h1);
        assert!(atlas.verify_chain());

        // Tampering a past observation without rebuilding the tail is detected.
        let mut tampered = atlas.clone();
        tampered.entries[1].observation.gate_verdict = "FAIL".to_owned();
        assert!(
            !tampered.verify_chain(),
            "an edited past entry must break the chain"
        );
    }
}
