#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::{borrow::ToOwned, string::ToString};
use alloc::{string::String, vec::Vec};
use core::fmt;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub struct Id(pub String);

impl Id {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
}

macro_rules! id_type {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
        pub struct $name(pub Id);
        impl $name {
            pub fn new(value: impl Into<String>) -> Self {
                Self(Id::new(value))
            }
        }
    };
}

id_type!(CoreId);
id_type!(TraceId);
id_type!(RunId);
id_type!(StitchId);
id_type!(GateReportId);
id_type!(ResidueId);
id_type!(ReplayRoot);
id_type!(Digest);
id_type!(LocatorId);
id_type!(PolicyId);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HashAlg {
    Blake3,
    Sha256,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreNode {
    pub id: CoreId,
    pub canonical_name: String,
    pub policy_root: PolicyId,
    pub signature_ok: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MirrorFacet {
    pub facet_id: Id,
    pub core_id: CoreId,
    pub sector: Sector,
    pub replay_root: ReplayRoot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Sector {
    #[default]
    Identity,
    Locator,
    Protocol,
    Timing,
    Risk,
    Replay,
    Focus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LocatorType {
    DirectIp,
    VpnExit,
    ProxyExit,
    Relay,
    Gateway,
    LocalOverlay,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Locator {
    pub id: LocatorId,
    pub locator_type: LocatorType,
    pub trusted: bool,
    pub risk_score: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionIntent {
    pub run: RunId,
    pub core: CoreNode,
    pub target_locator: LocatorId,
    pub capability_witness: bool,
    pub ttl_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct StitchCandidate {
    pub id: StitchId,
    pub run: RunId,
    pub core: CoreNode,
    pub facet: MirrorFacet,
    pub locator: Locator,
    pub capability_witness: bool,
    pub seam_ok: bool,
    pub boundary_complete: bool,
    pub replay_ready: bool,
    pub focus_ready: bool,
    pub ttl_epoch: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GateId {
    Core,
    Mirror,
    Locator,
    Bcik,
    Hypercube,
    Capability,
    Fiber,
    Privacy,
    Boundary,
    Focus,
    Replay,
    Dissolution,
}

impl GateId {
    pub const ALL: [GateId; 12] = [
        GateId::Core,
        GateId::Mirror,
        GateId::Locator,
        GateId::Bcik,
        GateId::Hypercube,
        GateId::Capability,
        GateId::Fiber,
        GateId::Privacy,
        GateId::Boundary,
        GateId::Focus,
        GateId::Replay,
        GateId::Dissolution,
    ];
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateWitness {
    pub gate: GateId,
    pub evidence: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResidueKind {
    Identity,
    Locator,
    Boundary,
    Capability,
    Protocol,
    Correlation,
    Focus,
    Replay,
    Timing,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundaryResidue {
    pub id: ResidueId,
    pub kind: ResidueKind,
    pub source_gate: GateId,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GateVerdict {
    Pass(GateWitness),
    Hold(BoundaryResidue),
    Refine(BoundaryResidue),
    Reject(BoundaryResidue),
    Quarantine(BoundaryResidue),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GateOutcomeKind {
    Pass,
    Hold,
    Refine,
    Reject,
    Quarantine,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateReport {
    pub id: GateReportId,
    pub outcome: GateOutcomeKind,
    pub witnesses: Vec<GateWitness>,
    pub residues: Vec<BoundaryResidue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchedulerState {
    pub theta0: PhaseVector,
    pub freq: FrequencyVector,
    pub seeded: bool,
    pub epoch: u64,
    pub ticks: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Phase(pub u32);

pub const PHASE_MODULUS: u32 = 1 << 20;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhaseVector {
    pub identity: Phase,
    pub locator: Phase,
    pub protocol: Phase,
    pub timing: Phase,
    pub risk: Phase,
    pub replay: Phase,
    pub focus: Phase,
}

impl PhaseVector {
    #[must_use]
    pub fn zero() -> Self {
        Self {
            identity: Phase(0),
            locator: Phase(0),
            protocol: Phase(0),
            timing: Phase(0),
            risk: Phase(0),
            replay: Phase(0),
            focus: Phase(0),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrequencyVector {
    pub identity: u32,
    pub locator: u32,
    pub protocol: u32,
    pub timing: u32,
    pub risk: u32,
    pub replay: u32,
    pub focus: u32,
}

impl FrequencyVector {
    #[must_use]
    pub fn deterministic() -> Self {
        Self {
            identity: 13,
            locator: 17,
            protocol: 19,
            timing: 23,
            risk: 29,
            replay: 31,
            focus: 37,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunDescriptor {
    pub run_id: RunId,
    pub policy_hash: Digest,
    pub scheduler: SchedulerState,
    pub crypto_algs: CryptoAlgSet,
    pub input_digest: Digest,
    pub prior_tensor_head: Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CryptoAlgSet {
    pub hash: HashAlg,
    pub signature: String,
    pub kex: String,
    pub aead: String,
}

impl Default for CryptoAlgSet {
    fn default() -> Self {
        Self {
            hash: HashAlg::Blake3,
            signature: "ed25519".to_owned(),
            kex: "x25519".to_owned(),
            aead: "chacha20poly1305".to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PipelineStep {
    Scheduler,
    Orbit,
    Locator,
    Bcik,
    Gates,
    Tensor,
    Focus,
    Replay,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceRecord {
    pub id: TraceId,
    pub run: RunId,
    pub step: PipelineStep,
    pub inputs: Vec<Digest>,
    pub outputs: Vec<Digest>,
    pub gate_report: Option<GateReportId>,
    pub residues: Vec<ResidueId>,
    pub prev_hash: Digest,
    pub entry_hash: Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayManifest {
    pub run: RunId,
    pub descriptor: RunDescriptor,
    pub trace_head: Digest,
    pub expected_outcome_digest: Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplayVerdict {
    Deterministic,
    Divergent {
        first_diff: PipelineStep,
        detail: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TensorEntry {
    pub id: StitchId,
    pub run: RunId,
    pub gate_report: GateReportId,
    pub replay_witness: bool,
    pub prev_hash: Digest,
    pub entry_hash: Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeOutcome {
    pub run: RunId,
    pub gate_report: GateReport,
    pub stitch: Option<TensorEntry>,
    pub residues: Vec<BoundaryResidue>,
    pub traces: Vec<TraceRecord>,
}

#[derive(Debug, Error)]
pub enum TypeError {
    #[error("serialization failed: {0}")]
    Serialization(String),
}

pub fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, TypeError> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(value, &mut out)
        .map_err(|e| TypeError::Serialization(e.to_string()))?;
    Ok(out)
}

pub fn digest_of<T: Serialize>(value: &T, alg: HashAlg) -> Result<Digest, TypeError> {
    let bytes = canonical_bytes(value)?;
    let hex = match alg {
        HashAlg::Blake3 => blake3::hash(&bytes).to_hex().to_string(),
        HashAlg::Sha256 => {
            let mut hasher = Sha256::new();
            hasher.update(&bytes);
            hex::encode(hasher.finalize())
        }
    };
    Ok(Digest::new(hex))
}

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_hash_is_stable() {
        let c = CoreNode {
            id: CoreId::new("c1"),
            canonical_name: "core".into(),
            policy_root: PolicyId::new("p1"),
            signature_ok: true,
        };
        let d1 = digest_of(&c, HashAlg::Blake3).expect("hash must work");
        let d2 = digest_of(&c, HashAlg::Blake3).expect("hash must work");
        assert_eq!(d1, d2);
    }
}
