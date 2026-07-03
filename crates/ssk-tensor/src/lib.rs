#![forbid(unsafe_code)]

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use ssk_types::{digest_of, Digest, GateReport, HashAlg, RunId, StitchId, TensorEntry};
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

pub trait LedgerBackend: Send + Sync {
    fn append(&self, entry: TensorEntry) -> Result<(), TensorError>;
    fn entries(&self) -> Result<Vec<TensorEntry>, TensorError>;
    fn verify(&self) -> Result<(), TensorError>;
}

#[derive(Default)]
pub struct MemoryBackend {
    entries: RwLock<Vec<TensorEntry>>,
}

impl MemoryBackend {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl LedgerBackend for MemoryBackend {
    fn append(&self, entry: TensorEntry) -> Result<(), TensorError> {
        self.entries.write().push(entry);
        Ok(())
    }

    fn entries(&self) -> Result<Vec<TensorEntry>, TensorError> {
        Ok(self.entries.read().clone())
    }

    fn verify(&self) -> Result<(), TensorError> {
        verify_chain(&self.entries.read())
    }
}

pub struct FileLedgerBackend {
    path: PathBuf,
}

impl FileLedgerBackend {
    #[must_use]
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }

    fn read_entries(&self) -> Result<Vec<TensorEntry>, TensorError> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let bytes = std::fs::read(&self.path)?;
        if bytes.is_empty() {
            return Ok(Vec::new());
        }
        Ok(serde_json::from_slice(&bytes)?)
    }

    fn write_entries(&self, entries: &[TensorEntry]) -> Result<(), TensorError> {
        let bytes = serde_json::to_vec_pretty(entries)?;
        std::fs::write(&self.path, bytes)?;
        Ok(())
    }
}

impl LedgerBackend for FileLedgerBackend {
    fn append(&self, entry: TensorEntry) -> Result<(), TensorError> {
        let mut entries = self.read_entries()?;
        entries.push(entry);
        self.write_entries(&entries)
    }

    fn entries(&self) -> Result<Vec<TensorEntry>, TensorError> {
        self.read_entries()
    }

    fn verify(&self) -> Result<(), TensorError> {
        verify_chain(&self.read_entries()?)
    }
}

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
        entry_hash: Digest::new("pending"),
    };
    entry.entry_hash = digest_of(&entry, HashAlg::Blake3)?;
    Ok(entry)
}

fn verify_chain(entries: &[TensorEntry]) -> Result<(), TensorError> {
    let mut prev = Digest::new("genesis");
    for e in entries {
        if e.prev_hash != prev {
            return Err(TensorError::VerificationFailed);
        }
        let mut expected = e.clone();
        expected.entry_hash = Digest::new("pending");
        expected.entry_hash = digest_of(&expected, HashAlg::Blake3)?;
        if expected.entry_hash != e.entry_hash {
            return Err(TensorError::VerificationFailed);
        }
        prev = e.entry_hash.clone();
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
            Digest::new("genesis"),
        )
        .expect("entry creation should succeed");
        backend.append(e1).expect("append should work");
        backend.verify().expect("verification should succeed");
    }
}
