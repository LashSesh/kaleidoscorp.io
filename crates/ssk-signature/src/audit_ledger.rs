//! Audit ledger — Chameleon `audit_ledger`.
//!
//! An in-memory append buffer with explicit, user-triggered JSONL export. The
//! Chameleon ledger is a flat buffer; the SSK side has a hash-chained,
//! append-only ledger (`ssk-audit`). This keeps the flat export the kernel's
//! tests expect while exposing serialized entries that the SSK ledger can chain
//! — the bridge to `chain_trace` lands where the daemon owns the durable ledger.

use std::path::{Path, PathBuf};

use serde::Serialize;

/// Errors the ledger can return on export.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LedgerError {
    #[error("an explicit export path is required")]
    NoPath,
    #[error("ledger io error: {0}")]
    Io(String),
    #[error("ledger encode error: {0}")]
    Encode(String),
}

/// In-memory audit buffer with explicit export.
#[derive(Clone, Debug, Default)]
pub struct AuditLedger {
    path: Option<PathBuf>,
    entries: Vec<serde_json::Value>,
}

impl AuditLedger {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_path(path: impl Into<PathBuf>) -> Self {
        AuditLedger {
            path: Some(path.into()),
            entries: Vec::new(),
        }
    }

    /// Append a serializable event as a canonical JSON value.
    ///
    /// # Errors
    /// [`LedgerError::Encode`] if the event cannot be serialized.
    pub fn append<T: Serialize>(&mut self, event: &T) -> Result<(), LedgerError> {
        let value = serde_json::to_value(event).map_err(|e| LedgerError::Encode(e.to_string()))?;
        self.entries.push(value);
        Ok(())
    }

    #[must_use]
    pub fn read_all(&self) -> &[serde_json::Value] {
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

    /// Render every entry as one canonical JSON line.
    ///
    /// # Errors
    /// [`LedgerError::Encode`] on serialization failure.
    pub fn export_jsonl(&self) -> Result<String, LedgerError> {
        let mut out = String::new();
        for entry in &self.entries {
            let line =
                serde_json::to_string(entry).map_err(|e| LedgerError::Encode(e.to_string()))?;
            out.push_str(&line);
            out.push('\n');
        }
        Ok(out)
    }

    /// Write the ledger as JSONL to `path` (or the ledger's configured path).
    ///
    /// # Errors
    /// [`LedgerError::NoPath`] if no path is available, or [`LedgerError::Io`].
    pub fn write_jsonl(&self, path: Option<&Path>) -> Result<PathBuf, LedgerError> {
        let destination = path
            .map(Path::to_path_buf)
            .or_else(|| self.path.clone())
            .ok_or(LedgerError::NoPath)?;
        if let Some(parent) = destination.parent() {
            std::fs::create_dir_all(parent).map_err(|e| LedgerError::Io(e.to_string()))?;
        }
        std::fs::write(&destination, self.export_jsonl()?)
            .map_err(|e| LedgerError::Io(e.to_string()))?;
        Ok(destination)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize)]
    struct Event {
        name: String,
        decision: String,
    }

    #[test]
    fn append_and_export_jsonl() {
        let mut ledger = AuditLedger::new();
        ledger
            .append(&Event {
                name: "a".to_owned(),
                decision: "PASS".to_owned(),
            })
            .unwrap();
        ledger
            .append(&Event {
                name: "b".to_owned(),
                decision: "OPTIMIZE".to_owned(),
            })
            .unwrap();
        assert_eq!(ledger.len(), 2);
        let jsonl = ledger.export_jsonl().unwrap();
        assert_eq!(jsonl.lines().count(), 2);
        assert!(jsonl.contains("\"decision\":\"PASS\""));
    }

    #[test]
    fn write_requires_a_path() {
        let ledger = AuditLedger::new();
        assert_eq!(ledger.write_jsonl(None).unwrap_err(), LedgerError::NoPath);
    }
}
