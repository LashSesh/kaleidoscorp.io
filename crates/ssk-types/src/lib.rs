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
id_type!(LocatorId);
id_type!(PolicyId);

/// Content-addressed hash value (Master Spec Ω+1 ch. 3.1). Backed by a real
/// 32-byte digest rather than an opaque string, so `content_id!`-derived ids
/// are genuinely computed from their object's canonical bytes, not chosen by
/// the caller. Serializes as the same lowercase-hex string the old
/// string-backed `Digest` produced, so persisted `GenericFileLedgerBackend`
/// JSON files remain readable across this change.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Digest(pub [u8; 32]);

impl Digest {
    /// Sentinel used as the `prev_hash` of the first entry in a hash chain.
    pub const GENESIS: Digest = Digest([0u8; 32]);
    /// Placeholder written into a `entry_hash`/`trace_head`-style field before
    /// its real value has been computed (mirrors the old `Digest::new("pending")`
    /// two-pass compute-then-overwrite pattern). Never compared for equality
    /// against a real digest by any passing code path.
    pub const PENDING: Digest = Digest([0u8; 32]);

    /// Parse a lowercase-hex-encoded 32-byte digest, e.g. as read back from a
    /// persisted ledger file.
    pub fn from_hex(s: &str) -> Result<Self, TypeError> {
        let bytes = hex::decode(s).map_err(|e| TypeError::Serialization(e.to_string()))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| TypeError::Serialization("digest must be exactly 32 bytes".to_owned()))?;
        Ok(Digest(arr))
    }

    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Digest").field(&self.to_hex()).finish()
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl Serialize for Digest {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Digest::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

/// Derives a content-addressed identifier: two objects with identical
/// canonical serialization always produce the same id (Master Spec Ω+1
/// ch. 3.1's identifier rule). Additive foundation infrastructure — no
/// existing id type is migrated to this macro yet; each id migrates only once
/// its owning object carries real canonical content to derive from.
#[macro_export]
macro_rules! content_id {
    ($name:ident) => {
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
        )]
        pub struct $name(pub $crate::Digest);

        impl $name {
            /// Derive the id from the canonical (CBOR) encoding of `value`.
            pub fn of<T: Serialize>(
                value: &T,
                alg: $crate::HashAlg,
            ) -> Result<Self, $crate::TypeError> {
                Ok(Self($crate::digest_of(value, alg)?))
            }
        }
    };
}

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

/// The class of foundation object a `CoreObject` impl identifies as (Master
/// Spec Ω+1 ch. 3.2). Additive — grows as later phases add object types
/// (`BcikStitch`, `CapabilityWitness`, `StitchEdge`, ...).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObjectKind {
    Core,
    MirrorFacet,
}

/// Which `ResidueKind` a `CoreObject` type escalates to if it fails
/// validation. A thin, additive wrapper: the real per-instance failure detail
/// still flows through `BoundaryResidue`/`ResidueKind` (ch. 9.2); this only
/// declares the type-level default, matching the gate table's "residue on
/// fail" column (ch. 11.2) for `CoreGate`/`MirrorGate`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResiduePolicy(pub ResidueKind);

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

/// The unified fault-detection taxonomy (Master Spec Ω+1 ch. 17.1). Additive
/// foundation vocabulary: no crate's public API returns this yet — each
/// foundation crate migrates its fallible boundary methods to return
/// `FaultKind` (directly or via a `From<LocalError>` bridge) only as its own
/// phase in `docs/OMEGA_CORE_CONFORMANCE_SPEC.md` lands, per that document's
/// Section E.5/T.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FaultKind {
    CoreNotCanonical,
    FacetNotRecoverable,
    LocatorUnavailable,
    SingleIpOverclaim,
    BcikSeamMissing,
    PchProjectionGap,
    CapabilityInvalid,
    PrivacyBudgetExceeded,
    TimingResidueHigh,
    FiberInvariantFailure,
    FocusAmbiguity,
    ReplayGap,
    ReanalysisMismatch,
    SilentResidueAttempt,
    DissolutionFailure,
    StorageFailure,
    ConfigInvalid,
    CryptoProviderError,
}

/// Fault severity (Master Spec Ω+1 ch. 17.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    High,
    Critical,
}

pub fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, TypeError> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(value, &mut out)
        .map_err(|e| TypeError::Serialization(e.to_string()))?;
    Ok(out)
}

pub fn digest_of<T: Serialize>(value: &T, alg: HashAlg) -> Result<Digest, TypeError> {
    let bytes = canonical_bytes(value)?;
    let raw: [u8; 32] = match alg {
        HashAlg::Blake3 => *blake3::hash(&bytes).as_bytes(),
        HashAlg::Sha256 => {
            let mut hasher = Sha256::new();
            hasher.update(&bytes);
            hasher
                .finalize()
                .as_slice()
                .try_into()
                .expect("sha256 output is 32 bytes")
        }
    };
    Ok(Digest(raw))
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

    #[test]
    fn digest_hex_round_trips() {
        let d = digest_of(&"payload", HashAlg::Blake3).expect("hash must work");
        let hex = d.to_hex();
        assert_eq!(Digest::from_hex(&hex).expect("valid hex"), d);
    }

    #[test]
    fn digest_serde_round_trips_as_hex_string() {
        let d = digest_of(&"payload", HashAlg::Sha256).expect("hash must work");
        let json = serde_json::to_string(&d).expect("serialize");
        assert_eq!(json, format!("\"{}\"", d.to_hex()));
        let back: Digest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, d);
    }

    content_id!(TestId);

    #[test]
    fn content_id_is_deterministic() {
        let a = TestId::of(&"payload", HashAlg::Blake3).expect("hash");
        let b = TestId::of(&"payload", HashAlg::Blake3).expect("hash");
        assert_eq!(a, b);
    }

    #[test]
    fn content_id_differs_for_different_input() {
        let a = TestId::of(&"payload-a", HashAlg::Blake3).expect("hash");
        let b = TestId::of(&"payload-b", HashAlg::Blake3).expect("hash");
        assert_ne!(a, b);
    }
}
