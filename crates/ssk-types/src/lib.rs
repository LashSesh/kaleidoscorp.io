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
id_type!(AuditRoot);
id_type!(KeyContextRef);
id_type!(SessionId);
id_type!(BoundaryRef);
id_type!(ResidueRef);

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

// `FacetId` is the first id migrated onto `content_id!` (Master Spec Ω+1
// ch. 3.1): `MirrorOrbit::derive` (ssk-core) now computes it from the
// facet's canonical inputs rather than accepting a caller-chosen string.
content_id!(FacetId);

/// Seed distinguishing one `MirrorOrbit` from another derived from the same
/// core (ch. 4.1). Feeds into `FacetId`'s content-addressed derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OrbitSeed(pub u64);

impl OrbitSeed {
    /// Deterministic default seed for a core's orbit, derived from the
    /// core's own id — so every orbit constructed for the same core (e.g. at
    /// derive time and later at recovery time) uses the same seed without
    /// the caller needing to persist and thread one through separately.
    #[must_use]
    pub fn for_core(core_id: &CoreId) -> Self {
        let digest = digest_of(core_id, HashAlg::Blake3).expect("a CoreId always hashes");
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&digest.0[..8]);
        Self(u64::from_le_bytes(buf))
    }
}

/// The core's canonical serialized form (ch. 4.1: `xc = Can(xc)` must hold).
/// Phase 1 placeholder: stores the form as an opaque string (continuing the
/// old `canonical_name` field's role under the spec's field name); the
/// fixed-point canonicalization invariant itself is enforced once
/// `Connection::canonicalize` (`ssk-core::connection`) gets a real body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalForm(pub String);

/// Placeholder for the real cryptographic signature over the canonical form
/// (ch. 4.1). Phase 1 treats "non-empty bytes" as "signed" — a real check on
/// real field content, not a bare bool — and defers verification against a
/// `SignatureProvider` to the capability/gate work (Section L, Phase 3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreSignature(pub Vec<u8>);

impl CoreSignature {
    #[must_use]
    pub fn is_present(&self) -> bool {
        !self.0.is_empty()
    }
}

/// Whether this core's identity/locator crossing story is open or closed
/// (ch. 4.1's `closure` field). Phase 1 placeholder — real semantics land
/// once BCIK's real crossing kernel (Phase 2) can report closure per core.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClosureState {
    Open,
    Closed,
}

/// A mirror facet's orientation relative to its core (ch. 4.1). Phase 1
/// placeholder — the PDF names the field but does not give its variants in
/// the excerpted text; `Forward`/`Reverse` is this document's own minimal,
/// disclosed design choice pending a richer definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Orientation {
    Forward,
    Reverse,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreNode {
    pub id: CoreId,
    pub canonical: CanonicalForm,
    pub signature: CoreSignature,
    pub policy_root: PolicyId,
    pub replay_root: ReplayRoot,
    pub audit_root: AuditRoot,
    pub closure: ClosureState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MirrorFacet {
    pub id: FacetId,
    pub core: CoreId,
    pub phase: PhaseVector,
    pub orientation: Orientation,
    pub sector: Sector,
    pub key_ctx: KeyContextRef,
    pub session: SessionId,
    pub policy: PolicyId,
    pub trace: TraceId,
    pub boundary: BoundaryRef,
    pub residue: ResidueRef,
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

/// Closed enum of egress classes (Master Spec Ω+1 ch. 4.3), 9 variants —
/// replaces the old 6-variant `LocatorType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LocatorKind {
    DirectIp,
    VpnExit,
    ProxyExit,
    Relay,
    Gateway,
    MultiHopPath,
    LocalOverlay,
    ControlledEgress,
    TestHarness,
}

/// Operator's trust in the egress surface (ch. 6.1, exact variants given).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustClass {
    Untrusted,
    Weak,
    Managed,
    Owned,
}

/// Budgeting class for locator selection (ch. 6.1, exact variants given).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CostClass {
    Free,
    Low,
    Metered,
    High,
}

/// Linkability/exposure risk estimate (ch. 6.1, exact variants given).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskClass {
    Low,
    Medium,
    High,
    Critical,
}

/// Liveness/route state from probes (ch. 6.1, exact variants given).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthStatus {
    Unknown,
    Live,
    Degraded,
    Down,
}

id_type!(EndpointRef);

/// Rotation-window/lifetime counter for a locator or a run (ch. 3.1/6.1).
/// Plain ordinal rather than an opaque string or content-addressed id, since
/// epochs are a monotonic counter, not a canonical object with its own
/// content to hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EpochId(pub u64);

/// Lifetime/expiry counter (ch. 4.3/5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Ttl(pub u64);

/// A scheduler tick count (ch. 12.1's `StitchTensorEntry.accepted_at`) —
/// distinct from `EpochId`: an epoch is a coarse policy/session generation,
/// a tick is the scheduler's own per-advance counter (`SchedulerState.ticks`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Tick(pub u64);

/// Route classification (ch. 4.3/6.4). Phase 1 placeholder — the excerpted
/// PDF text names the field but does not enumerate `RouteClass`'s variants;
/// this minimal, disclosed set stands in until the funnel-DAG work
/// (Section G.2) needs a richer one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RouteClass {
    Direct,
    SingleHop,
    MultiHop,
    Fallback,
    Denied,
}

/// Transport classification (ch. 4.3). Phase 1 placeholder — same disclosure
/// as `RouteClass`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransportClass {
    Tcp,
    Udp,
    Tls,
    Unknown,
}

/// Timing-shaping classification for a locator ray (ch. 4.2). Phase 1
/// placeholder — same disclosure as `RouteClass`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimingClass {
    Immediate,
    Delayed,
    Batched,
}

/// The observable, accountable metadata of one egress resource
/// (Master Spec Ω+1 ch. 4.3/6.1) — replaces the old 4-field `Locator`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocatorFacet {
    pub id: LocatorId,
    pub kind: LocatorKind,
    pub endpoint: EndpointRef,
    pub route: RouteClass,
    pub transport: TransportClass,
    pub epoch: EpochId,
    pub ttl: Ttl,
    pub trust: TrustClass,
    pub cost: CostClass,
    pub risk: RiskClass,
    pub health: HealthStatus,
    pub trace: TraceId,
    /// Phase 1 bridge fields: today's thin gate checks (`LocatorGate`/
    /// `FiberGate`/`PrivacyGate` in `ssk-gates`) compare a simple trusted
    /// flag and a numeric risk threshold. Rewiring those gates against the
    /// real `trust`/`risk` enum classes above is Phase 3's job (spec
    /// Section K); until then these two fields preserve today's exact gate
    /// behavior undisturbed.
    pub trusted: bool,
    pub risk_score: u8,
}

id_type!(SessionIntent);
// One edge in the funnel-DAG (ch. 6.3's `EdgeId`).
id_type!(EdgeId);

/// How a `StitchEdge` transforms a crossing (ch. 6.3, verbatim variants) —
/// a closed enum: "there is no opaque tunnel variant."
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EdgeTransform {
    Routing,
    Framing,
    TransportAdapt,
    RelayHandoff,
}

/// Why an edge is present in the graph (ch. 6.3's `PolicyReason`). Phase 6
/// placeholder — the excerpted PDF text names the field but not a closed
/// variant set; a free-text reason stands in until a policy authoring
/// surface needs a stricter taxonomy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyReason(pub String);

/// One ordinary transition between two locators in the funnel-DAG (Master
/// Spec Ω+1 ch. 6.3, verbatim field list). Every field is mandatory by
/// construction — ch. 6.3's "edge explicitness" invariant ("an edge missing
/// any of these fields fails deserialization validation") holds directly
/// from this being a plain struct with no `Option`/`#[serde(default)]`
/// fields: neither a struct literal nor `serde` deserialization can produce
/// one with a field silently missing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StitchEdge {
    pub id: EdgeId,
    pub src: LocatorId,
    pub dst: LocatorId,
    pub map: EdgeTransform,
    pub lifetime: Ttl,
    pub policy_reason: PolicyReason,
    pub capability: Option<CapabilityId>,
    pub boundary: BoundaryRef,
    pub trace: TraceId,
}

/// A multi-dependency transition (ch. 6.3's `HyperEdge`) — this document's
/// own minimal, disclosed elaboration: the excerpted PDF text names the
/// type but does not enumerate its fields. Modeled as "all of `requires`
/// must already be reachable before `produces` becomes reachable," the
/// natural hypergraph generalization of `StitchEdge`'s single `src → dst`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HyperEdge {
    pub id: EdgeId,
    pub requires: Vec<LocatorId>,
    pub produces: LocatorId,
    pub lifetime: Ttl,
    pub policy_reason: PolicyReason,
    pub trace: TraceId,
}

/// The funnel-DAG itself (ch. 6.3, verbatim field list).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct LocatorGraph {
    pub nodes: Vec<LocatorFacet>,
    pub edges: Vec<StitchEdge>,
    pub hyperedges: Vec<HyperEdge>,
}

/// The result of `select_path` (ch. 6.4) — this document's own disclosed
/// elaboration: the ordered chain of edges actually selected, plus the
/// final reachable locator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocatorPath {
    pub edges: Vec<EdgeId>,
    pub destination: LocatorId,
}

/// Whether a birefringent split's identity ray requires a replay witness
/// (ch. 4.2). Phase 1 placeholder — the excerpted text names the field but
/// not its variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplayNeed {
    Required,
    Optional,
}

/// "What the core intends to do." (Master Spec Ω+1 ch. 4.2, verbatim field
/// list.)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityRay {
    pub core_ref: CoreId,
    pub session_intent: SessionIntent,
    pub key_context: KeyContextRef,
    pub app_policy: PolicyId,
    pub replay_need: ReplayNeed,
    pub residue_policy: ResiduePolicy,
}

/// A set of permitted locator kinds (ch. 4.2's `LocatorTypeSet`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocatorTypeSet(pub Vec<LocatorKind>);

/// Bounded risk allowance for locator selection (ch. 4.2). Phase 1
/// placeholder scale (0-100, higher = more risk tolerated).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskBudget(pub u8);

/// Bounded cost allowance for locator selection (ch. 4.2). Phase 1
/// placeholder scale (0-100, higher = more cost tolerated).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CostBudget(pub u8);

/// "How the connection may appear externally." (Master Spec Ω+1 ch. 4.2,
/// verbatim field list.) Deliberately not `From`/`Into`-convertible with
/// `IdentityRay` — the plane-separation invariant is enforced at compile
/// time by this omission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocatorRay {
    pub allowed_locator_types: LocatorTypeSet,
    pub route_class: RouteClass,
    pub transport_class: TransportClass,
    pub timing_class: TimingClass,
    pub risk_budget: RiskBudget,
    pub cost_budget: CostBudget,
}

// `CapabilityId` is content-addressed (Master Spec Ω+1 ch. 3.1/5.2): a
// capability witness has real canonical content (claim/scope/issuer/...) to
// derive an id from, unlike the still-opaque ids left untouched in Phase 1.
content_id!(CapabilityId);

id_type!(IssuerRef);
id_type!(ReplayRef);
// A per-run audit reference (ch. 14.2's `RunOutcome::DissolveRejectQuarantine.audit`)
// — distinct from `AuditRoot` (a core's own audit chain root, ch. 4.1):
// this points at one run's audit trail entry, not the whole chain.
id_type!(AuditRef);
// A reference to a stored replay report (ch. 13.1's `FocusReport.replay`,
// ch. 14.2's `RunOutcome::Pass.replay`) — distinct from `ReplayRef` (a
// stitch-level replay witness reference, ch. 4.1). No replay-report
// registry exists yet; this id type lands ahead of that registry so
// `FocusReport`/`RunOutcome` can carry the field the PDF specifies.
id_type!(ReplayReportRef);

/// A capability's declared claim, e.g. "may use locator class Relay in
/// epoch E" (ch. 5.2). Phase 2 placeholder: an opaque string; a richer
/// structured claim grammar is not required by any current acceptance
/// criterion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityClaim(pub String);

/// Action + facet-class binding a capability witness is scoped to (ch. 5.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scope {
    pub action: String,
    pub facet_class: ObjectKind,
}

/// Which kind of subject a capability witness is bound to (ch. 5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SubjectClass {
    Core,
    Facet,
    Locator,
}

/// Opaque proof bytes, validated only by the issuing provider (ch. 5.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofBytes(pub Vec<u8>);

/// Scoped evidence that a facet, action, locator use or stitch event is
/// admissible — not identity, and proves only its declared claim
/// (Master Spec Ω+1 ch. 5.2, verbatim field list).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityWitness {
    pub id: CapabilityId,
    pub claim: CapabilityClaim,
    pub scope: Scope,
    pub issuer: IssuerRef,
    pub subject_class: SubjectClass,
    pub epoch: EpochId,
    pub expiry: Ttl,
    pub proof: ProofBytes,
    pub trace: TraceId,
}

/// A typed transport operation carrying a valid payload or control frame
/// (ch. 4.4). Phase 2 placeholder — the excerpted PDF text names
/// `ProtocolFiber::Frame` generically; this closed enum is this document's
/// own minimal, disclosed classification pending a richer fiber model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FiberType {
    Control,
    Data,
}

/// Evidence that a BCIK seam is closed (ch. 9.1's `Sigma`). Content-addressed
/// over the crossing's inputs so it is genuinely tamper-evident, not a bare
/// flag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeamWitness(pub Digest);

/// The boundary operator's record of one crossing (ch. 9.1's `partial-d`).
/// Phase 2 placeholder — a closed/open flag plus detail; the residual
/// projector's exact numeric tolerance (`epsilon_stitch`, ch. 9.1's closure
/// definition) is not modeled yet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundaryRecord {
    pub closed: bool,
    pub detail: String,
}

/// A boundary-closed identity/locator/fiber binding (Master Spec Ω+1
/// ch. 9.1, verbatim field list) — the real payload `CrossOutcome::Closed`
/// now carries, replacing the old unit-like `Closed` variant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BcikStitch {
    pub id: StitchId,
    pub facet: FacetId,
    pub locator: LocatorId,
    pub fiber: FiberType,
    pub phase: PhaseVector,
    pub capability: Option<CapabilityId>,
    pub seam: SeamWitness,
    pub boundary: BoundaryRecord,
    pub residues: Vec<ResidueId>,
    pub gate_report: Option<GateReportId>,
    pub trace: TraceId,
    pub replay: ReplayRef,
}

/// Either a closed stitch or a boundary residue — never a silent success and
/// never a silent drop (ch. 9.1's "no silent crossing" invariant). Has no
/// unit success variant: the caller is forced to handle either outcome.
///
/// `Closed(BcikStitch)` is kept unboxed to match the PDF's literal signature
/// exactly rather than `Closed(Box<BcikStitch>)`; the resulting enum-size
/// lint is accepted deliberately.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CrossOutcome {
    Closed(BcikStitch),
    Residue(BoundaryResidue),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionIntent {
    pub run: RunId,
    pub core: CoreNode,
    pub target_locator: LocatorId,
    pub capability: Option<CapabilityWitness>,
    pub ttl_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct StitchCandidate {
    pub id: StitchId,
    pub run: RunId,
    pub core: CoreNode,
    pub facet: MirrorFacet,
    pub locator: LocatorFacet,
    pub capability: Option<CapabilityWitness>,
    pub seam_ok: bool,
    pub boundary_complete: bool,
    pub replay_ready: bool,
    pub focus_ready: bool,
    pub ttl_epoch: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
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

/// The closed residue taxonomy **K** (IMRT A4, Def. H). Every non-integrated
/// field fragment is classified into exactly one of these kinds. The theory
/// fixes K at 11 kinds; the last two — [`Cospectral`](ResidueKind::Cospectral)
/// (a spectral-equal-but-non-isomorphic hold, L4) and
/// [`FieldProjection`](ResidueKind::FieldProjection) (the un-measured remainder
/// of a lossy projection, IMDF 7) — were previously missing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
    /// Spectrally equal but not isomorphic — a Kospektral hold (L4, `Spec= ∧
    /// G≇H ⟹ Hold`) whose un-decided mass must be conserved, not passed.
    Cospectral,
    /// The remainder of a lossy projection W: field content the projection did
    /// not carry across (IMDF 7 / Satz 9.13), made visible instead of dropped.
    FieldProjection,
}

impl ResidueKind {
    /// The complete closed taxonomy K (11 kinds).
    pub const ALL: [ResidueKind; 11] = [
        ResidueKind::Identity,
        ResidueKind::Locator,
        ResidueKind::Boundary,
        ResidueKind::Capability,
        ResidueKind::Protocol,
        ResidueKind::Correlation,
        ResidueKind::Focus,
        ResidueKind::Replay,
        ResidueKind::Timing,
        ResidueKind::Cospectral,
        ResidueKind::FieldProjection,
    ];
}

/// The lifecycle **Status** of a residue in the CounterHorizon triple
/// `H: X → K × Status × NextAction` (IMRT A4, Def. H). Replaces the earlier
/// `open_obligation` bool so the disposition is a first-class tri-state rather
/// than a collapsed flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResidueStatus {
    /// Unresolved and blocking — a standing obligation (fail-closed default).
    Open,
    /// Acknowledged and tracked, but explicitly non-blocking for this run.
    Deferred,
    /// Discharged — the fragment was integrated or accepted; no obligation.
    Resolved,
}

/// The **NextAction** directive of the CounterHorizon triple — what the field
/// must do about a residue (IMRT A4, Def. H). Distinct from `Status`: a residue
/// can be `Open` with a `Reacquire` directive, or `Deferred` with `Accept`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NextAction {
    /// Quarantine/hold the surface until the fragment is resolved.
    Hold,
    /// Re-observe the source to recover the missing fragment.
    Reacquire,
    /// Raise severity / route to a higher authority (ρ* escalation).
    Escalate,
    /// Re-run reanalysis binding the residue as an input.
    Reanalyze,
    /// Accept the fragment as a known, tolerated loss — no further action.
    Accept,
}

/// The visible currency of "no silent loss" (IMRT A4, Satz 13.5) — the complete
/// residue **5-tuple** `(Source, Fragment, Reason, Status, NextAction)` in a
/// class of the closed taxonomy K.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundaryResidue {
    pub id: ResidueId,
    /// The taxonomy-K class this fragment falls into.
    pub kind: ResidueKind,
    /// **Source**: which gate/part produced the residue.
    pub source_gate: GateId,
    /// **Fragment**: the concrete non-integrated field part (what was lost).
    /// `None` when the emitter has only a reason, not an isolable fragment.
    pub fragment: Option<String>,
    /// **Reason**: why the fragment could not be integrated.
    pub detail: String,
    pub severity: Severity,
    pub origin: TraceId,
    /// **Status**: the lifecycle disposition (`Open`/`Deferred`/`Resolved`).
    pub status: ResidueStatus,
    /// **NextAction**: the remediation directive.
    pub next_action: NextAction,
}

impl BoundaryResidue {
    /// Construct from the legacy 7-tuple: `open_obligation` maps to
    /// `Status`/`NextAction` (`true → Open + Hold`, `false → Resolved + Accept`)
    /// and no isolable `Fragment` is attached. Prefer [`new_full`](Self::new_full)
    /// or the `with_*` builders at call sites that carry a fragment or a specific
    /// directive.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: ResidueId,
        kind: ResidueKind,
        source_gate: GateId,
        detail: impl Into<String>,
        severity: Severity,
        origin: TraceId,
        open_obligation: bool,
    ) -> Self {
        let (status, next_action) = if open_obligation {
            (ResidueStatus::Open, NextAction::Hold)
        } else {
            (ResidueStatus::Resolved, NextAction::Accept)
        };
        Self {
            id,
            kind,
            source_gate,
            fragment: None,
            detail: detail.into(),
            severity,
            origin,
            status,
            next_action,
        }
    }

    /// Construct the complete 5-tuple with an explicit `Fragment`, `Status`, and
    /// `NextAction`.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new_full(
        id: ResidueId,
        kind: ResidueKind,
        source_gate: GateId,
        fragment: Option<String>,
        detail: impl Into<String>,
        severity: Severity,
        origin: TraceId,
        status: ResidueStatus,
        next_action: NextAction,
    ) -> Self {
        Self {
            id,
            kind,
            source_gate,
            fragment,
            detail: detail.into(),
            severity,
            origin,
            status,
            next_action,
        }
    }

    /// Attach the isolable `Fragment` that was lost.
    #[must_use]
    pub fn with_fragment(mut self, fragment: impl Into<String>) -> Self {
        self.fragment = Some(fragment.into());
        self
    }

    /// Set the `NextAction` directive.
    #[must_use]
    pub fn with_next_action(mut self, next_action: NextAction) -> Self {
        self.next_action = next_action;
        self
    }

    /// Set the lifecycle `Status`.
    #[must_use]
    pub fn with_status(mut self, status: ResidueStatus) -> Self {
        self.status = status;
        self
    }

    /// Whether this residue is a standing, blocking obligation. Only `Open`
    /// residues block; `Deferred` are acknowledged-non-blocking and `Resolved`
    /// are discharged. Preserves the legacy `open_obligation` predicate.
    #[must_use]
    pub fn open_obligation(&self) -> bool {
        matches!(self.status, ResidueStatus::Open)
    }

    /// The CounterHorizon mapping `H(r) = (class, status, next_action)`
    /// (IMRT A4, Def. H). Every residue yields a complete triple — there is no
    /// residue whose disposition is undefined.
    #[must_use]
    pub fn h_triple(&self) -> (ResidueKind, ResidueStatus, NextAction) {
        (self.kind, self.status, self.next_action)
    }
}

/// Append-only register of residues emitted during one run (ch. 9.2's
/// `R_res`). Additive over the plain `Vec<BoundaryResidue>` collections
/// scattered through earlier phases' code — new call sites should prefer
/// this over constructing a bare `Vec` directly.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResidueRegister {
    entries: Vec<BoundaryResidue>,
}

impl ResidueRegister {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn emit(&mut self, r: BoundaryResidue) -> ResidueId {
        let id = r.id.clone();
        self.entries.push(r);
        id
    }

    pub fn open_obligations(&self) -> impl Iterator<Item = &BoundaryResidue> {
        self.entries.iter().filter(|r| r.open_obligation())
    }

    #[must_use]
    pub fn entries(&self) -> &[BoundaryResidue] {
        &self.entries
    }

    /// The number of residues emitted so far. Monotone non-decreasing over the
    /// register's life — there is no removal API (append-only by construction).
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The CounterHorizon triples `H(r)` for every registered residue, in emit
    /// order — the full `X → K × Status × NextAction` mapping.
    pub fn horizon(&self) -> impl Iterator<Item = (ResidueKind, ResidueStatus, NextAction)> + '_ {
        self.entries.iter().map(BoundaryResidue::h_triple)
    }
}

/// The closed set of **origin edges** of the field (IMRT A4, Def 11.6): the
/// structural boundary a residue arose at. The residue cloud X partitions
/// disjointly over these classes; any residue that cannot be attributed to an
/// origin edge escalates to the ρ\* meta-residue instead of silently belonging
/// nowhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum EdgeClass {
    /// The self/identity edge (L0–L1).
    SelfEdge,
    /// The observer edge (L2 perception).
    Observer,
    /// The aperture/focus edge (L2–L3 projection).
    Aperture,
    /// The gate edge (L5 decision).
    Gate,
    /// The boundary/seam edge (L9 crossing).
    Boundary,
    /// The replay/reanalysis edge (L6).
    Replay,
}

impl EdgeClass {
    /// The origin edge a residue is attributed to, or `None` (→ ρ\*) if the
    /// residue lacks a real origin trace. Total over the taxonomy K.
    #[must_use]
    pub fn of(residue: &BoundaryResidue) -> Option<EdgeClass> {
        // A residue with no real origin trace cannot be placed on an edge — it is
        // a ρ* candidate (Inv 11.7).
        if residue.origin.0 .0.is_empty() {
            return None;
        }
        Some(match residue.kind {
            ResidueKind::Identity => EdgeClass::SelfEdge,
            ResidueKind::Locator | ResidueKind::Boundary => EdgeClass::Boundary,
            ResidueKind::Correlation | ResidueKind::Timing => EdgeClass::Observer,
            ResidueKind::Focus | ResidueKind::FieldProjection => EdgeClass::Aperture,
            ResidueKind::Capability | ResidueKind::Protocol | ResidueKind::Cospectral => {
                EdgeClass::Gate
            }
            ResidueKind::Replay => EdgeClass::Replay,
        })
    }
}

/// A read-only view over a [`ResidueRegister`] that partitions its residue
/// cloud X into disjoint origin-edge classes plus the ρ\* meta-residue catch-all
/// (IMRT A4, Def 11.6 / Inv 11.7). Guarantees the partition is total and
/// disjoint: every residue lands in exactly one edge class, or in ρ\*.
pub struct ResidueCloud<'a> {
    entries: &'a [BoundaryResidue],
}

impl<'a> ResidueCloud<'a> {
    #[must_use]
    pub fn of(register: &'a ResidueRegister) -> Self {
        ResidueCloud {
            entries: register.entries(),
        }
    }

    #[must_use]
    pub fn from_slice(entries: &'a [BoundaryResidue]) -> Self {
        ResidueCloud { entries }
    }

    /// The disjoint edge-class partition of X: each edge class mapped to the
    /// residues attributed to it. Residues with no origin edge are excluded
    /// (they appear in [`rho_star`](Self::rho_star)).
    #[must_use]
    pub fn partition(&self) -> alloc::collections::BTreeMap<EdgeClass, Vec<&'a BoundaryResidue>> {
        let mut map: alloc::collections::BTreeMap<EdgeClass, Vec<&'a BoundaryResidue>> =
            alloc::collections::BTreeMap::new();
        for r in self.entries {
            if let Some(edge) = EdgeClass::of(r) {
                map.entry(edge).or_default().push(r);
            }
        }
        map
    }

    /// The ρ\* meta-residue: every residue that lacks an origin edge. A
    /// non-empty ρ\* is a critical error signal (residues must be attributable),
    /// but it is *kept*, never dropped — it is the closure-guaranteeing catch-all.
    #[must_use]
    pub fn rho_star(&self) -> Vec<&'a BoundaryResidue> {
        self.entries
            .iter()
            .filter(|r| EdgeClass::of(r).is_none())
            .collect()
    }

    /// Whether the partition is total and disjoint: the edge classes and ρ\*
    /// together account for every residue in X exactly once.
    #[must_use]
    pub fn is_total_disjoint_partition(&self) -> bool {
        let partitioned: usize = self.partition().values().map(Vec::len).sum();
        let rho = self.rho_star().len();
        // Disjoint (edge classes are exclusive by construction) + total: every
        // residue is either on exactly one edge or in ρ*.
        partitioned + rho == self.entries.len()
    }
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

/// A recorded PRNG seed for `SchedulerMode::Seeded` (ch. 7.2) — stored in the
/// `RunDescriptor` so replay is exact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SchedulerSeed(pub u64);

/// Both modes are deterministic given their inputs; the difference is only
/// whether a seed perturbs increments (Master Spec Ω+1 ch. 7.2, verbatim).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SchedulerMode {
    /// Pure: phase advances by a fixed `FrequencyVector`. Fully reproducible.
    Deterministic,
    /// Seeded: a recorded seed drives a deterministic PRNG that jitters
    /// increments; the seed is stored in the `RunDescriptor` so replay is exact.
    Seeded(SchedulerSeed),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchedulerState {
    pub theta0: PhaseVector,
    pub freq: FrequencyVector,
    pub mode: SchedulerMode,
    pub epoch: u64,
    pub ticks: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Phase(pub u32);

pub const PHASE_MODULUS: u32 = 1 << 20;

/// Visibility half-width for the toroidal-distance predicate (ch. 7.1,
/// verbatim).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Window {
    pub epsilon: u32,
}

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

/// A hash-chained entry in the persistent Stitch Tensor (Master Spec Ω+1
/// ch. 12.1, verbatim field list) — carries the real `BcikStitch` payload
/// rather than `TensorEntry`'s flat id-only record, so an accepted stitch's
/// full crossing evidence survives into the persisted tensor, not just its
/// identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StitchTensorEntry {
    pub id: StitchId,
    pub stitch: BcikStitch,
    pub gate_report: GateReportId,
    pub accepted_at: Tick,
    pub epoch: EpochId,
    pub ttl: Ttl,
    pub prev_hash: Digest,
    pub entry_hash: Digest,
}

/// One gate-passed candidate ready for tensor acceptance (ch. 12.1's
/// `Accepted`, referenced but not field-enumerated by the excerpted PDF
/// text). This document's own necessary elaboration: the minimal field set
/// `StitchTensor::apply_sorted` needs to build a `StitchTensorEntry` and to
/// sort deterministically by `(epoch, stitch.id)` per ch. 12.2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Accepted {
    pub stitch: BcikStitch,
    pub gate_report: GateReportId,
    pub accepted_at: Tick,
    pub epoch: EpochId,
    pub ttl: Ttl,
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
            canonical: CanonicalForm("core".into()),
            signature: CoreSignature(alloc::vec![1, 2, 3]),
            policy_root: PolicyId::new("p1"),
            replay_root: ReplayRoot::new("replay:c1"),
            audit_root: AuditRoot::new("audit:c1"),
            closure: ClosureState::Closed,
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

    // G9 (A4): the residue is the complete 5-tuple (Source, Fragment, Reason,
    // Status, NextAction) in a class of the closed taxonomy K (11 kinds).
    #[test]
    fn residue_is_the_complete_five_tuple_over_taxonomy_k() {
        // The taxonomy K is exactly 11 kinds, including the previously-missing
        // Cospectral and FieldProjection.
        assert_eq!(ResidueKind::ALL.len(), 11);
        assert!(ResidueKind::ALL.contains(&ResidueKind::Cospectral));
        assert!(ResidueKind::ALL.contains(&ResidueKind::FieldProjection));

        // The full constructor carries every tuple field.
        let r = BoundaryResidue::new_full(
            ResidueId::new("r1"),
            ResidueKind::FieldProjection,
            GateId::Focus,
            Some("hidden.body".to_owned()),
            "projection dropped the body sub-surface",
            Severity::High,
            TraceId::new("t1"),
            ResidueStatus::Open,
            NextAction::Reacquire,
        );
        assert_eq!(r.source_gate, GateId::Focus); // Source
        assert_eq!(r.fragment.as_deref(), Some("hidden.body")); // Fragment
        assert_eq!(r.detail, "projection dropped the body sub-surface"); // Reason
        assert_eq!(r.status, ResidueStatus::Open); // Status
        assert_eq!(r.next_action, NextAction::Reacquire); // NextAction
        assert!(r.open_obligation(), "Open is a standing obligation");

        // The legacy 7-arg constructor maps open_obligation → Status/NextAction
        // and preserves the open_obligation() predicate exactly.
        let held = BoundaryResidue::new(
            ResidueId::new("r2"),
            ResidueKind::Boundary,
            GateId::Boundary,
            "seam open",
            Severity::High,
            TraceId::new("t2"),
            true,
        );
        assert_eq!(held.status, ResidueStatus::Open);
        assert_eq!(held.next_action, NextAction::Hold);
        assert!(held.open_obligation());
        assert!(
            held.fragment.is_none(),
            "no isolable fragment via legacy new"
        );

        let resolved = BoundaryResidue::new(
            ResidueId::new("r3"),
            ResidueKind::Boundary,
            GateId::Boundary,
            "seam closed",
            Severity::Info,
            TraceId::new("t3"),
            false,
        );
        assert_eq!(resolved.status, ResidueStatus::Resolved);
        assert!(!resolved.open_obligation());

        // Deferred is acknowledged-but-non-blocking: conserved, not an obligation.
        let deferred = held.with_status(ResidueStatus::Deferred);
        assert!(
            !deferred.open_obligation(),
            "a deferred residue is conserved but does not block"
        );

        // Only Open residues surface as open obligations in a register.
        let mut reg = ResidueRegister::new();
        reg.emit(r);
        reg.emit(resolved);
        reg.emit(deferred);
        assert_eq!(reg.entries().len(), 3);
        assert_eq!(
            reg.open_obligations().count(),
            1,
            "only the Open one blocks"
        );
    }

    // G10 (A4, Def. H): the register is append-only — length is monotone
    // non-decreasing and there is no removal API — and the CounterHorizon
    // mapping H yields a complete (class, status, next_action) triple for every
    // entry, with no residue left undefined.
    #[test]
    fn counter_horizon_register_is_append_only_and_h_is_total() {
        let mut reg = ResidueRegister::new();
        assert!(reg.is_empty());

        let mut prev = 0usize;
        for (i, (kind, status, action)) in [
            (
                ResidueKind::Cospectral,
                ResidueStatus::Open,
                NextAction::Hold,
            ),
            (
                ResidueKind::FieldProjection,
                ResidueStatus::Deferred,
                NextAction::Accept,
            ),
            (
                ResidueKind::Capability,
                ResidueStatus::Resolved,
                NextAction::Reanalyze,
            ),
        ]
        .into_iter()
        .enumerate()
        {
            reg.emit(BoundaryResidue::new_full(
                ResidueId::new(format!("r{i}")),
                kind,
                GateId::Focus,
                Some(format!("frag{i}")),
                "reason",
                Severity::Low,
                TraceId::new(format!("t{i}")),
                status,
                action,
            ));
            // Monotone: length only ever grows.
            assert!(reg.len() > prev, "emit must strictly grow the register");
            prev = reg.len();
        }

        // H(r) is total: every registered residue yields its full triple, in
        // emit order, matching what was emitted.
        let horizon: Vec<_> = reg.horizon().collect();
        assert_eq!(
            horizon,
            vec![
                (
                    ResidueKind::Cospectral,
                    ResidueStatus::Open,
                    NextAction::Hold
                ),
                (
                    ResidueKind::FieldProjection,
                    ResidueStatus::Deferred,
                    NextAction::Accept
                ),
                (
                    ResidueKind::Capability,
                    ResidueStatus::Resolved,
                    NextAction::Reanalyze
                ),
            ],
            "H maps every residue to a complete (class, status, next_action) triple"
        );
        assert_eq!(horizon.len(), reg.len(), "H is defined for every entry");
    }

    // G8 (A4, Def 11.6 / Inv 11.7): the residue cloud X partitions disjointly
    // over origin-edge classes, with any origin-less residue escalated to the
    // ρ* meta-residue — union == X, pairwise disjoint, nothing dropped.
    #[test]
    fn residue_cloud_partitions_disjointly_with_rho_star_catch_all() {
        let mut reg = ResidueRegister::new();
        // Residues on distinct edges (each with a real origin trace).
        let placed = [
            (ResidueKind::Identity, EdgeClass::SelfEdge),
            (ResidueKind::Boundary, EdgeClass::Boundary),
            (ResidueKind::Correlation, EdgeClass::Observer),
            (ResidueKind::Focus, EdgeClass::Aperture),
            (ResidueKind::Capability, EdgeClass::Gate),
            (ResidueKind::Replay, EdgeClass::Replay),
        ];
        for (i, (kind, _edge)) in placed.iter().enumerate() {
            reg.emit(BoundaryResidue::new(
                ResidueId::new(format!("p{i}")),
                *kind,
                GateId::Focus,
                "reason",
                Severity::Low,
                TraceId::new(format!("origin-{i}")),
                true,
            ));
        }
        // A residue with NO real origin trace → ρ*.
        reg.emit(BoundaryResidue::new(
            ResidueId::new("orphan"),
            ResidueKind::Identity,
            GateId::Focus,
            "no origin edge",
            Severity::High,
            TraceId::new(""), // empty origin
            true,
        ));

        let cloud = ResidueCloud::of(&reg);
        let partition = cloud.partition();
        let rho = cloud.rho_star();

        // Every placed residue landed on its expected edge.
        for (kind, edge) in placed {
            assert!(
                partition
                    .get(&edge)
                    .is_some_and(|rs| rs.iter().any(|r| r.kind == kind)),
                "{kind:?} must be attributed to {edge:?}"
            );
        }
        // The orphan is in ρ*, not in any edge class.
        assert_eq!(rho.len(), 1, "the origin-less residue escalates to ρ*");
        assert_eq!(rho[0].id, ResidueId::new("orphan"));

        // Total + disjoint: the six edges + ρ* account for all seven residues.
        assert!(cloud.is_total_disjoint_partition());
        let partitioned: usize = partition.values().map(Vec::len).sum();
        assert_eq!(partitioned + rho.len(), reg.len());
        assert_eq!(partitioned, 6);

        // ρ* is kept, never dropped — a non-empty ρ* is visible.
        assert!(!rho.is_empty(), "ρ* is a visible catch-all, not silence");
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
