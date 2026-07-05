#![forbid(unsafe_code)]

use parking_lot::{Mutex, RwLock};
use serde::{de::DeserializeOwned, Serialize};
use ssk_types::{
    digest_of, Accepted, BcikStitch, BoundaryResidue, Digest, EpochId, FaultKind, GateId,
    GateReport, HashAlg, ResidueId, ResidueKind, ResidueRegister, RunId, Severity, StitchId,
    StitchTensorEntry, TensorEntry,
};
use std::collections::HashMap;
use std::io::Write;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum TensorError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serde error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("type error: {0}")]
    Types(#[from] ssk_types::TypeError),
    #[error("hash-chain verification failed")]
    VerificationFailed,
}

/// Entry-type-agnostic storage: append and list entries. Hash-chain
/// verification is deliberately not part of this trait since different entry
/// types compute/represent their chain hash differently (see `LedgerBackend`
/// for the `TensorEntry`-specific verification built on top of this).
pub trait GenericLedgerBackend<E>: Send + Sync
where
    E: Send + Sync,
{
    fn append(&self, entry: E) -> Result<(), TensorError>;
    fn entries(&self) -> Result<Vec<E>, TensorError>;
}

/// `TensorEntry`-specific ledger backend. `append`/`entries` are inherited
/// unchanged from the `GenericLedgerBackend<TensorEntry>` supertrait (and,
/// per Rust's supertrait method visibility rules, are callable directly on
/// any `L: LedgerBackend`-bounded value with no extra import); `verify()` is
/// the one addition, using `ssk_types::Digest`-based canonical-CBOR
/// hash-chain checks.
pub trait LedgerBackend: GenericLedgerBackend<TensorEntry> {
    fn verify(&self) -> Result<(), TensorError> {
        verify_chain(&GenericLedgerBackend::entries(self)?)
    }

    /// Verify the chain **and** that it matches a trusted `(len, head)`
    /// checkpoint the caller persisted out-of-band. `verify()` alone only
    /// proves prefix integrity — any prefix of a valid chain is itself a
    /// valid chain, so silently deleting trailing entries still verifies.
    /// Anchoring to an independently-recorded length and head is what
    /// actually detects that truncation.
    fn verify_against_head(
        &self,
        trusted_len: usize,
        trusted_head: Digest,
    ) -> Result<(), TensorError> {
        let entries = GenericLedgerBackend::entries(self)?;
        verify_chain(&entries)?;
        let head = entries.last().map_or(Digest::GENESIS, |e| e.entry_hash);
        if entries.len() != trusted_len || head != trusted_head {
            return Err(TensorError::VerificationFailed);
        }
        Ok(())
    }
}

impl<T: GenericLedgerBackend<TensorEntry>> LedgerBackend for T {}

/// `StitchTensorEntry`-specific storage backend (Master Spec Ω+1 ch. 12.1's
/// `StorageBackend`). Reuses the existing, already-tested
/// `GenericLedgerBackend<E>` infrastructure as a supertrait rather than
/// forking it — the same pattern `LedgerBackend` itself already uses above.
/// Two disclosed deviations from the PDF's literal signature, both needed to
/// build on shared-reference (`RwLock`-backed) infrastructure honestly:
/// `append` is inherited from `GenericLedgerBackend` and so takes `&self`
/// (not `&mut self`) and returns `TensorError` (not `FaultKind`); `get`/
/// `iter` degrade to `None`/empty on a storage read failure rather than
/// panicking — callers that need the underlying error can call
/// `GenericLedgerBackend::entries` directly.
pub trait StorageBackend: GenericLedgerBackend<StitchTensorEntry> {
    fn get(&self, id: &StitchId) -> Option<StitchTensorEntry> {
        self.entries().ok()?.into_iter().find(|e| &e.id == id)
    }

    fn iter(&self) -> Box<dyn Iterator<Item = StitchTensorEntry> + '_> {
        Box::new(self.entries().unwrap_or_default().into_iter())
    }

    fn head(&self) -> Digest {
        self.entries()
            .ok()
            .and_then(|es| es.last().map(|e| e.entry_hash))
            .unwrap_or(Digest::GENESIS)
    }

    /// Verify the `StitchTensorEntry` hash chain (genesis-rooted, `prev_hash`
    /// links, `entry_hash` recomputed over each entry). Unlike `TensorEntry`,
    /// nothing previously validated this chain at all — `StitchTensor::open`
    /// trusted `entries.last()` verbatim, so a forged or hand-edited entry was
    /// accepted with no check.
    fn verify(&self) -> Result<(), TensorError> {
        verify_stitch_chain(&self.entries()?)
    }

    /// As [`LedgerBackend::verify_against_head`]: verify the chain and that it
    /// matches a trusted `(len, head)` checkpoint, so trailing-entry deletion
    /// (which chain-prefix verification alone cannot see) is detected too.
    fn verify_against_head(
        &self,
        trusted_len: usize,
        trusted_head: Digest,
    ) -> Result<(), TensorError> {
        let entries = self.entries()?;
        verify_stitch_chain(&entries)?;
        let head = entries.last().map_or(Digest::GENESIS, |e| e.entry_hash);
        if entries.len() != trusted_len || head != trusted_head {
            return Err(TensorError::VerificationFailed);
        }
        Ok(())
    }
}

impl<T: GenericLedgerBackend<StitchTensorEntry>> StorageBackend for T {}

/// The accepted-stitch graph `G_s` (ch. 12.1's `StitchGraph`) — a
/// content-addressed index of every stitch accepted into the tensor so far.
/// Phase 4 placeholder for real edge/adjacency structure: the PDF's
/// excerpted text names the type but does not enumerate connectivity
/// queries beyond membership, so this holds exactly that until a consumer
/// needs more (e.g. Section G's funnel-DAG work).
#[derive(Debug, Clone, Default)]
pub struct StitchGraph {
    stitches: HashMap<StitchId, BcikStitch>,
}

impl StitchGraph {
    pub fn insert(&mut self, stitch: &BcikStitch) {
        self.stitches.insert(stitch.id.clone(), stitch.clone());
    }

    #[must_use]
    pub fn contains(&self, id: &StitchId) -> bool {
        self.stitches.contains_key(id)
    }

    #[must_use]
    pub fn get(&self, id: &StitchId) -> Option<&BcikStitch> {
        self.stitches.get(id)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.stitches.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.stitches.is_empty()
    }
}

/// The persistent Stitch Tensor (Master Spec Ω+1 ch. 12.1-12.2, verbatim
/// shape) — the append-only, hash-chained, gate-passed-only record of
/// accepted stitches. Only reachable via `apply_sorted`, which only ever
/// receives `Accepted` values (themselves only constructible from a
/// `Connection<GatePassed>`, Section E.3) — so "gate failure preserves the
/// tensor" (ch. 12.2's theorem) holds by construction: nothing calls
/// `apply_sorted` with an empty `Vec` on a failed candidate, and an empty
/// `Vec` is a genuine no-op (`ST(t+1) = ST(t)`).
pub struct StitchTensor {
    graph: StitchGraph,
    head: Digest,
    backend: Box<dyn StorageBackend>,
}

impl StitchTensor {
    /// Rebuilds `graph`/`head` from whatever the backend already persists, so
    /// re-opening a `StitchTensor` over an existing file backend resumes with
    /// a correct in-memory graph rather than silently starting empty. The
    /// persisted chain is verified first — a forged or hand-edited entry (or a
    /// broken `prev_hash` link) is rejected rather than trusted verbatim.
    pub fn open(backend: Box<dyn StorageBackend>) -> Result<Self, FaultKind> {
        backend.verify().map_err(|_| FaultKind::StorageFailure)?;
        let entries = backend.entries().map_err(|_| FaultKind::StorageFailure)?;
        let mut graph = StitchGraph::default();
        for e in &entries {
            graph.insert(&e.stitch);
        }
        let head = entries.last().map_or(Digest::GENESIS, |e| e.entry_hash);
        Ok(Self {
            graph,
            head,
            backend,
        })
    }

    /// Deterministic ordering by `(epoch, StitchId)` for replay stability
    /// (ch. 12.2, verbatim), then chains and appends each entry in order.
    pub fn apply_sorted(&mut self, accepted: Vec<Accepted>) -> Result<Vec<StitchId>, FaultKind> {
        let mut acc = accepted;
        acc.sort_by(|a, b| (a.epoch, &a.stitch.id).cmp(&(b.epoch, &b.stitch.id)));

        let mut ids = Vec::new();
        for a in acc {
            let entry = self.chain(a)?;
            self.backend
                .append(entry.clone())
                .map_err(|_| FaultKind::StorageFailure)?;
            self.graph.insert(&entry.stitch);
            self.head = entry.entry_hash;
            ids.push(entry.id);
        }
        Ok(ids)
    }

    fn chain(&self, a: Accepted) -> Result<StitchTensorEntry, FaultKind> {
        let mut entry = StitchTensorEntry {
            id: a.stitch.id.clone(),
            stitch: a.stitch,
            gate_report: a.gate_report,
            accepted_at: a.accepted_at,
            epoch: a.epoch,
            ttl: a.ttl,
            prev_hash: self.head,
            entry_hash: Digest::PENDING,
        };
        entry.entry_hash =
            digest_of(&entry, HashAlg::Blake3).map_err(|_| FaultKind::StorageFailure)?;
        Ok(entry)
    }

    #[must_use]
    pub fn head(&self) -> Digest {
        self.head
    }

    #[must_use]
    pub fn graph(&self) -> &StitchGraph {
        &self.graph
    }
}

/// Real TTL/epoch sweep over the persistent tensor (Master Spec Ω+1
/// ch. 21's `dissolution.ttl_required`/`finalize_residues_on_expiry`) —
/// replaces the bare `ttl_epoch != 0` presence check used elsewhere in this
/// workspace (e.g. `DissolutionGate`) with a genuine "has this entry's
/// lifetime actually elapsed" computation over real epoch arithmetic.
#[derive(Debug, Default)]
pub struct DissolutionManager;

impl DissolutionManager {
    /// An entry is expired once `current_epoch` has advanced at least
    /// `ttl` epochs past the entry's own accepted `epoch` — the literal
    /// reading of `StitchTensorEntry`'s `epoch`+`ttl` fields as "TTL
    /// counted in epochs."
    #[must_use]
    pub fn is_expired(entry: &StitchTensorEntry, current_epoch: EpochId) -> bool {
        current_epoch.0.saturating_sub(entry.epoch.0) >= entry.ttl.0
    }

    /// Sweeps every entry a `StorageBackend` holds, returning the ids of
    /// every one whose TTL has elapsed as of `current_epoch` — a real scan
    /// over real entries, not a per-candidate flag check.
    pub fn sweep(
        backend: &impl StorageBackend,
        current_epoch: EpochId,
    ) -> Result<Vec<StitchId>, TensorError> {
        Ok(backend
            .entries()?
            .into_iter()
            .filter(|e| Self::is_expired(e, current_epoch))
            .map(|e| e.id)
            .collect())
    }

    /// Sweeps expired entries and **finalizes** each into a
    /// `ResidueRegister` (ch. 21's `dissolution.finalize_residues_on_expiry`)
    /// — every dissolved stitch leaves a typed, hash-chained `Timing` residue
    /// carrying an open obligation, so an expiry is a visible, auditable event
    /// rather than a silent drop (the tensor itself is append-only and is not
    /// mutated; dissolution is recorded, not erased). Returns the emitted
    /// residue ids, parallel to the swept stitch ids.
    pub fn finalize_expired(
        backend: &impl StorageBackend,
        current_epoch: EpochId,
        register: &mut ResidueRegister,
    ) -> Result<Vec<ResidueId>, TensorError> {
        let mut emitted = Vec::new();
        for entry in backend.entries()? {
            if !Self::is_expired(&entry, current_epoch) {
                continue;
            }
            let residue = BoundaryResidue::new(
                ResidueId::new(format!("dissolution:{}", entry.id.0 .0)),
                ResidueKind::Timing,
                GateId::Dissolution,
                format!(
                    "stitch {} expired at epoch {} (accepted epoch {}, ttl {})",
                    entry.id.0 .0, current_epoch.0, entry.epoch.0, entry.ttl.0
                ),
                Severity::Low,
                entry.stitch.trace.clone(),
                true,
            );
            emitted.push(register.emit(residue));
        }
        Ok(emitted)
    }
}

#[derive(Default)]
pub struct GenericMemoryBackend<E> {
    entries: RwLock<Vec<E>>,
}

impl<E> GenericMemoryBackend<E> {
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(Vec::new()),
        }
    }
}

impl<E: Clone + Send + Sync> GenericMemoryBackend<E> {
    /// Overwrite the whole in-memory entry list. Used for compaction and for
    /// deliberately constructing an invalid chain in tests.
    pub fn replace_all(&self, entries: Vec<E>) {
        *self.entries.write() = entries;
    }
}

impl<E: Clone + Send + Sync> GenericLedgerBackend<E> for GenericMemoryBackend<E> {
    fn append(&self, entry: E) -> Result<(), TensorError> {
        self.entries.write().push(entry);
        Ok(())
    }

    fn entries(&self) -> Result<Vec<E>, TensorError> {
        Ok(self.entries.read().clone())
    }
}

/// `TensorEntry`-flavored in-memory backend. Kept as a type alias so every
/// existing `MemoryBackend::new()` call site keeps compiling unchanged.
pub type MemoryBackend = GenericMemoryBackend<TensorEntry>;

/// A file-backed ledger. Writes are **atomic**: each `append` serializes the
/// whole entry list to a sibling temp file, `fsync`s it, then renames it onto
/// the target path — `rename` is an atomic filesystem operation, so a
/// concurrent reader (in this process or another) always sees either the
/// complete pre-append file or the complete post-append file, never a
/// truncated or half-written one. That kills the worst failure mode a naive
/// truncate-and-rewrite has: a reader landing mid-write, seeing zero or
/// partial bytes, and `verify()` reporting a false "ledger-ok" on what looks
/// like an empty chain.
///
/// `write_lock` additionally serializes concurrent `append` calls **within
/// this process** (e.g. two threads sharing one `Arc<GenericFileLedgerBackend<E>>`),
/// so a same-process read-modify-write race cannot silently drop an entry.
///
/// Residual, disclosed limitation: two entirely separate **processes**
/// appending to the same path at the same instant can still race the
/// read-modify-write (both read N entries, both write N+1, one rename wins) —
/// a lost *append*, not corruption or a false-positive verify. Closing that
/// residual gap needs OS-level cross-process file locking, which this crate
/// does not yet provide.
pub struct GenericFileLedgerBackend<E> {
    path: PathBuf,
    write_lock: Mutex<()>,
    _marker: PhantomData<E>,
}

impl<E> GenericFileLedgerBackend<E> {
    #[must_use]
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            write_lock: Mutex::new(()),
            _marker: PhantomData,
        }
    }
}

impl<E: Serialize + DeserializeOwned + Clone + Send + Sync> GenericFileLedgerBackend<E> {
    fn read_entries(&self) -> Result<Vec<E>, TensorError> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let bytes = std::fs::read(&self.path)?;
        if bytes.is_empty() {
            return Ok(Vec::new());
        }
        Ok(serde_json::from_slice(&bytes)?)
    }

    fn write_entries(&self, entries: &[E]) -> Result<(), TensorError> {
        let bytes = serde_json::to_vec_pretty(entries)?;
        let dir = self
            .path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        let mut tmp = tempfile::NamedTempFile::new_in(&dir)?;
        tmp.write_all(&bytes)?;
        tmp.as_file().sync_all()?;
        tmp.persist(&self.path).map_err(|e| e.error)?;
        Ok(())
    }
}

impl<E: Serialize + DeserializeOwned + Clone + Send + Sync> GenericLedgerBackend<E>
    for GenericFileLedgerBackend<E>
{
    fn append(&self, entry: E) -> Result<(), TensorError> {
        let _guard = self.write_lock.lock();
        let mut entries = self.read_entries()?;
        entries.push(entry);
        self.write_entries(&entries)
    }

    fn entries(&self) -> Result<Vec<E>, TensorError> {
        self.read_entries()
    }
}

/// `TensorEntry`-flavored file backend. Kept as a type alias so every existing
/// `FileLedgerBackend::new(path)` call site keeps compiling unchanged.
pub type FileLedgerBackend = GenericFileLedgerBackend<TensorEntry>;

pub fn make_entry(
    run: RunId,
    stitch: StitchId,
    gate_report: &GateReport,
    replay_witness: bool,
    prev_hash: Digest,
) -> Result<TensorEntry, TensorError> {
    let mut entry = TensorEntry {
        id: stitch,
        run,
        gate_report: gate_report.id.clone(),
        replay_witness,
        prev_hash,
        entry_hash: Digest::PENDING,
    };
    entry.entry_hash = digest_of(&entry, HashAlg::Blake3)?;
    Ok(entry)
}

fn verify_chain(entries: &[TensorEntry]) -> Result<(), TensorError> {
    let mut prev = Digest::GENESIS;
    for e in entries {
        if e.prev_hash != prev {
            return Err(TensorError::VerificationFailed);
        }
        let mut expected = e.clone();
        expected.entry_hash = Digest::PENDING;
        expected.entry_hash = digest_of(&expected, HashAlg::Blake3)?;
        if expected.entry_hash != e.entry_hash {
            return Err(TensorError::VerificationFailed);
        }
        prev = e.entry_hash;
    }
    Ok(())
}

/// `StitchTensorEntry`'s hash-chain check, mirroring [`verify_chain`] exactly
/// (genesis-rooted, `prev_hash` links, `entry_hash` recomputed with the field
/// reset to `PENDING`) but for the richer stitch-carrying entry type.
fn verify_stitch_chain(entries: &[StitchTensorEntry]) -> Result<(), TensorError> {
    let mut prev = Digest::GENESIS;
    for e in entries {
        if e.prev_hash != prev {
            return Err(TensorError::VerificationFailed);
        }
        let mut expected = e.clone();
        expected.entry_hash = Digest::PENDING;
        expected.entry_hash = digest_of(&expected, HashAlg::Blake3)?;
        if expected.entry_hash != e.entry_hash {
            return Err(TensorError::VerificationFailed);
        }
        prev = e.entry_hash;
    }
    Ok(())
}

/// `StitchTensorEntry`-flavored in-memory backend, so tests can build a
/// `StitchTensor` without a real file on disk.
pub type StitchMemoryBackend = GenericMemoryBackend<StitchTensorEntry>;

#[cfg(test)]
mod tests {
    use super::*;
    use ssk_types::{
        BoundaryRecord, EpochId, FacetId, GateReportId, HashAlg, LocatorId, PhaseVector,
        SeamWitness, StitchId, TraceId, Ttl,
    };

    fn sample_stitch(id: &str) -> BcikStitch {
        BcikStitch {
            id: StitchId::new(id),
            facet: FacetId::of(&id, HashAlg::Blake3).expect("hash"),
            locator: LocatorId::new("l1"),
            fiber: ssk_types::FiberType::Data,
            phase: PhaseVector::zero(),
            capability: None,
            seam: SeamWitness(Digest::GENESIS),
            boundary: BoundaryRecord {
                closed: true,
                detail: "ok".into(),
            },
            residues: Vec::new(),
            gate_report: None,
            trace: TraceId::new(format!("trace-{id}")),
            replay: ssk_types::ReplayRef::new(format!("replay-{id}")),
        }
    }

    fn sample_accepted(id: &str, epoch: u64) -> Accepted {
        Accepted {
            stitch: sample_stitch(id),
            gate_report: GateReportId::new(format!("gr-{id}")),
            accepted_at: ssk_types::Tick(0),
            epoch: EpochId(epoch),
            ttl: Ttl(100),
        }
    }

    #[test]
    fn apply_sorted_orders_by_epoch_then_id_and_chains_hashes() {
        let backend: StitchMemoryBackend = GenericMemoryBackend::new();
        let mut tensor = StitchTensor::open(Box::new(backend)).expect("open");

        let ids = tensor
            .apply_sorted(vec![sample_accepted("b", 1), sample_accepted("a", 0)])
            .expect("apply_sorted");

        // "a" (epoch 0) must be chained before "b" (epoch 1) regardless of
        // input order (ch. 12.2's deterministic-ordering requirement).
        assert_eq!(ids, vec![StitchId::new("a"), StitchId::new("b")]);
        assert_eq!(tensor.graph().len(), 2);
        assert!(tensor.graph().contains(&StitchId::new("a")));
        assert_ne!(tensor.head(), Digest::GENESIS);
    }

    #[test]
    fn empty_apply_sorted_preserves_the_tensor() {
        let backend: StitchMemoryBackend = GenericMemoryBackend::new();
        let mut tensor = StitchTensor::open(Box::new(backend)).expect("open");
        let head_before = tensor.head();

        let ids = tensor.apply_sorted(Vec::new()).expect("apply_sorted");

        assert!(ids.is_empty());
        assert_eq!(tensor.head(), head_before);
        assert!(tensor.graph().is_empty());
    }

    /// Builds a genuinely chained `StitchTensorEntry` the same way
    /// `StitchTensor::chain` does (entry_hash computed over the entry with
    /// itself reset to `PENDING`), so it passes `verify_stitch_chain`.
    fn chained_stitch_entry(id: &str, prev_hash: Digest) -> StitchTensorEntry {
        let stitch = sample_stitch(id);
        let mut entry = StitchTensorEntry {
            id: stitch.id.clone(),
            stitch,
            gate_report: GateReportId::new(format!("gr-{id}")),
            accepted_at: ssk_types::Tick(0),
            epoch: EpochId(0),
            ttl: Ttl(100),
            prev_hash,
            entry_hash: Digest::PENDING,
        };
        entry.entry_hash = digest_of(&entry, HashAlg::Blake3).expect("hash");
        entry
    }

    #[test]
    fn open_rebuilds_graph_and_head_from_existing_entries() {
        let backend: StitchMemoryBackend = GenericMemoryBackend::new();
        let entry = chained_stitch_entry("x", Digest::GENESIS);
        backend.append(entry).expect("append");

        let reopened = StitchTensor::open(Box::new(backend)).expect("reopen");
        assert_eq!(reopened.graph().len(), 1);
        assert!(reopened.graph().contains(&StitchId::new("x")));
        assert_ne!(reopened.head(), Digest::GENESIS);
    }

    // StitchTensor::open must reject a chain a caller has tampered with,
    // rather than trusting entries.last() verbatim.
    #[test]
    fn open_rejects_a_forged_entry() {
        let backend: StitchMemoryBackend = GenericMemoryBackend::new();
        let mut entry = chained_stitch_entry("x", Digest::GENESIS);
        // Tamper with the payload after the hash was computed over the real
        // stitch id — entry_hash no longer matches.
        entry.stitch.id = StitchId::new("forged");
        backend.append(entry).expect("append");

        let result = StitchTensor::open(Box::new(backend));
        assert!(
            result.is_err(),
            "a forged entry must be rejected, not accepted verbatim"
        );
    }

    // A broken prev_hash link (mid-chain deletion/reordering) must also be
    // rejected by open(), not silently trusted.
    #[test]
    fn open_rejects_a_broken_prev_hash_link() {
        let backend: StitchMemoryBackend = GenericMemoryBackend::new();
        let first = chained_stitch_entry("a", Digest::GENESIS);
        let head_a = first.entry_hash;
        backend.append(first).expect("append");
        // "b" should chain from head_a, but instead (wrongly) claims GENESIS.
        let second = chained_stitch_entry("b", Digest::GENESIS);
        backend.append(second).expect("append");
        assert_ne!(head_a, Digest::GENESIS);

        let result = StitchTensor::open(Box::new(backend));
        assert!(result.is_err(), "a broken prev_hash link must be rejected");
    }

    fn entry_with(id: &str, epoch: u64, ttl: u64) -> StitchTensorEntry {
        let stitch = sample_stitch(id);
        StitchTensorEntry {
            id: stitch.id.clone(),
            stitch,
            gate_report: GateReportId::new(format!("gr-{id}")),
            accepted_at: ssk_types::Tick(0),
            epoch: EpochId(epoch),
            ttl: Ttl(ttl),
            prev_hash: Digest::GENESIS,
            entry_hash: digest_of(&format!("seed-{id}"), HashAlg::Blake3).expect("hash"),
        }
    }

    #[test]
    fn is_expired_true_once_current_epoch_reaches_accepted_epoch_plus_ttl() {
        let entry = entry_with("x", 10, 5);
        assert!(!DissolutionManager::is_expired(&entry, EpochId(14)));
        assert!(DissolutionManager::is_expired(&entry, EpochId(15)));
        assert!(DissolutionManager::is_expired(&entry, EpochId(20)));
    }

    #[test]
    fn sweep_returns_only_expired_entries() {
        let backend: StitchMemoryBackend = GenericMemoryBackend::new();
        backend
            .append(entry_with("fresh", 10, 100))
            .expect("append");
        backend.append(entry_with("stale", 0, 5)).expect("append");

        let expired = DissolutionManager::sweep(&backend, EpochId(10)).expect("sweep");
        assert_eq!(expired, vec![StitchId::new("stale")]);
    }

    #[test]
    fn sweep_over_an_empty_backend_finds_nothing() {
        let backend: StitchMemoryBackend = GenericMemoryBackend::new();
        let expired = DissolutionManager::sweep(&backend, EpochId(1000)).expect("sweep");
        assert!(expired.is_empty());
    }

    #[test]
    fn finalize_expired_emits_a_timing_residue_per_expired_entry() {
        let backend: StitchMemoryBackend = GenericMemoryBackend::new();
        backend
            .append(entry_with("fresh", 10, 100))
            .expect("append");
        backend.append(entry_with("stale", 0, 5)).expect("append");

        let mut register = ResidueRegister::new();
        let emitted = DissolutionManager::finalize_expired(&backend, EpochId(10), &mut register)
            .expect("finalize");

        assert_eq!(emitted.len(), 1);
        assert_eq!(register.entries().len(), 1);
        assert_eq!(register.entries()[0].kind, ResidueKind::Timing);
        assert_eq!(register.open_obligations().count(), 1);
    }

    #[test]
    fn memory_hash_chain_verifies() {
        let backend = MemoryBackend::new();
        let report = GateReport {
            id: ssk_types::GateReportId::new("g1"),
            outcome: ssk_types::GateOutcomeKind::Pass,
            witnesses: Vec::new(),
            residues: Vec::new(),
        };

        let e1 = make_entry(
            RunId::new("r1"),
            StitchId::new("s1"),
            &report,
            true,
            Digest::GENESIS,
        )
        .expect("entry creation should succeed");
        backend.append(e1).expect("append should work");
        backend.verify().expect("verification should succeed");
    }

    #[test]
    fn generic_memory_backend_works_with_a_non_tensor_entry_type() {
        #[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
        struct Toy {
            value: u32,
        }

        let backend: GenericMemoryBackend<Toy> = GenericMemoryBackend::new();
        backend.append(Toy { value: 1 }).expect("append");
        backend.append(Toy { value: 2 }).expect("append");
        assert_eq!(
            backend.entries().expect("entries"),
            vec![Toy { value: 1 }, Toy { value: 2 }]
        );

        backend.replace_all(vec![Toy { value: 9 }]);
        assert_eq!(backend.entries().expect("entries"), vec![Toy { value: 9 }]);
    }

    #[test]
    fn generic_file_backend_persists_a_non_tensor_entry_type() {
        #[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
        struct Toy {
            value: u32,
        }

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("toy.json");

        {
            let backend: GenericFileLedgerBackend<Toy> = GenericFileLedgerBackend::new(&path);
            backend.append(Toy { value: 1 }).expect("append");
            backend.append(Toy { value: 2 }).expect("append");
        }

        let reopened: GenericFileLedgerBackend<Toy> = GenericFileLedgerBackend::new(&path);
        assert_eq!(
            reopened.entries().expect("entries"),
            vec![Toy { value: 1 }, Toy { value: 2 }]
        );
    }

    #[test]
    fn file_backend_leaves_no_temp_file_behind_after_append() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("ledger.json");
        let file_backend: FileLedgerBackend = GenericFileLedgerBackend::new(&path);

        let report = GateReport {
            id: ssk_types::GateReportId::new("g1"),
            outcome: ssk_types::GateOutcomeKind::Pass,
            witnesses: Vec::new(),
            residues: Vec::new(),
        };
        let entry = make_entry(
            RunId::new("r1"),
            StitchId::new("s1"),
            &report,
            true,
            Digest::GENESIS,
        )
        .expect("entry");
        file_backend.append(entry).expect("append");

        // Only the target file exists in the directory -- the atomic-rename
        // write leaves no stray .tmp artifact and no torn intermediate state.
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .expect("read_dir")
            .map(|e| e.expect("entry").file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("ledger.json")]);
        assert!(file_backend.verify().is_ok());
    }

    // verify() alone only proves prefix integrity -- a chain with its trailing
    // entry deleted is still a valid (shorter) chain. verify_against_head must
    // catch exactly that, by anchoring to an independently-recorded (len, head).
    #[test]
    fn verify_against_head_detects_trailing_truncation() {
        let backend = MemoryBackend::new();
        let report = GateReport {
            id: ssk_types::GateReportId::new("g1"),
            outcome: ssk_types::GateOutcomeKind::Pass,
            witnesses: Vec::new(),
            residues: Vec::new(),
        };
        let e1 = make_entry(
            RunId::new("r1"),
            StitchId::new("s1"),
            &report,
            true,
            Digest::GENESIS,
        )
        .expect("entry");
        backend.append(e1.clone()).expect("append");
        let e2 = make_entry(
            RunId::new("r1"),
            StitchId::new("s2"),
            &report,
            true,
            e1.entry_hash,
        )
        .expect("entry");
        backend.append(e2.clone()).expect("append");

        let trusted_len = backend.entries().unwrap().len();
        let trusted_head = e2.entry_hash;
        assert!(backend
            .verify_against_head(trusted_len, trusted_head)
            .is_ok());

        // Truncate the trailing entry: verify() alone still passes (the
        // remaining prefix is a genuinely valid chain), but the trusted
        // checkpoint no longer matches.
        backend.replace_all(vec![e1]);
        assert!(
            backend.verify().is_ok(),
            "a valid prefix still verifies alone"
        );
        assert!(
            backend
                .verify_against_head(trusted_len, trusted_head)
                .is_err(),
            "verify_against_head must catch the truncated tail that verify() alone cannot"
        );
    }

    #[test]
    fn stitch_verify_against_head_detects_trailing_truncation() {
        let backend: StitchMemoryBackend = GenericMemoryBackend::new();
        let first = chained_stitch_entry("a", Digest::GENESIS);
        let head_a = first.entry_hash;
        backend.append(first).expect("append");
        let second = chained_stitch_entry("b", head_a);
        let head_b = second.entry_hash;
        backend.append(second).expect("append");

        assert!(backend.verify_against_head(2, head_b).is_ok());
        backend.replace_all(vec![chained_stitch_entry("a", Digest::GENESIS)]);
        assert!(
            backend.verify_against_head(2, head_b).is_err(),
            "trailing deletion of a StitchTensorEntry must be caught"
        );
    }
}
