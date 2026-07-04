#![forbid(unsafe_code)]

use parking_lot::RwLock;
use serde::{de::DeserializeOwned, Serialize};
use ssk_types::{digest_of, Digest, GateReport, HashAlg, RunId, StitchId, TensorEntry};
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
}

impl<T: GenericLedgerBackend<TensorEntry>> LedgerBackend for T {}

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

pub struct GenericFileLedgerBackend<E> {
    path: PathBuf,
    _marker: PhantomData<E>,
}

impl<E> GenericFileLedgerBackend<E> {
    #[must_use]
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
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
        std::fs::write(&self.path, bytes)?;
        Ok(())
    }
}

impl<E: Serialize + DeserializeOwned + Clone + Send + Sync> GenericLedgerBackend<E>
    for GenericFileLedgerBackend<E>
{
    fn append(&self, entry: E) -> Result<(), TensorError> {
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
