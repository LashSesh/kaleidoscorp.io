//! The durable, ACL-protected state store (SPEC_TAURI_GUI.md §3): replaces the
//! `%TEMP%` receipt store with an atomically-written snapshot in ProgramData.
//!
//! The snapshot holds everything needed to recover the authoritative kill-switch
//! state after a crash: the logical state, the held rollback receipt, the
//! monotone version, and the hash-chained audit journal. It is written whole,
//! atomically (temp file + fsync + rename), under the broker's operation lock —
//! so a crash mid-write never yields a torn snapshot, and a single writer never
//! races itself.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use ssk_boundary::{BoundaryAuditEntry, EnforcementReceipt, KillSwitchState};

use crate::error::HelperError;

const SNAPSHOT_FILE: &str = "killswitch.cbor";
const SNAPSHOT_SCHEMA: u32 = 1;

/// The full persisted snapshot of the kill-switch security state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersistedState {
    /// Schema version so a future format change is detected, not mis-decoded.
    pub schema_version: u32,
    pub logical_state: KillSwitchState,
    pub receipt: Option<EnforcementReceipt>,
    pub state_version: u64,
    /// The hash-chained kill-switch audit journal (verified on rehydrate).
    pub journal: Vec<BoundaryAuditEntry>,
}

impl PersistedState {
    #[must_use]
    pub fn new(
        logical_state: KillSwitchState,
        receipt: Option<EnforcementReceipt>,
        state_version: u64,
        journal: Vec<BoundaryAuditEntry>,
    ) -> Self {
        PersistedState {
            schema_version: SNAPSHOT_SCHEMA,
            logical_state,
            receipt,
            state_version,
            journal,
        }
    }
}

/// The durable store seam. The broker persists through this; tests inject an
/// in-memory or temp-dir implementation.
pub trait ReceiptStore: Send {
    /// Atomically persist the snapshot (whole-file, crash-safe).
    ///
    /// # Errors
    /// [`HelperError::Store`] on any IO failure.
    fn save(&self, state: &PersistedState) -> Result<(), HelperError>;

    /// Load the persisted snapshot, or `None` if the store is empty (first run).
    ///
    /// # Errors
    /// [`HelperError::Store`] on IO failure; [`HelperError::CorruptState`] if a
    /// present snapshot cannot be decoded.
    fn load(&self) -> Result<Option<PersistedState>, HelperError>;
}

/// The default ProgramData-based state directory
/// (`%ProgramData%\ScorpioSync\state`), or a conventional path off-Windows.
#[must_use]
pub fn default_state_dir() -> PathBuf {
    if let Some(program_data) = std::env::var_os("ProgramData") {
        PathBuf::from(program_data)
            .join("ScorpioSync")
            .join("state")
    } else {
        PathBuf::from("/var/lib/scorpiosync/state")
    }
}

/// A crash-safe, ACL-protected file store.
pub struct FileReceiptStore {
    dir: PathBuf,
}

impl FileReceiptStore {
    /// Open (creating if needed) the store at `dir`, asserting a restrictive
    /// DACL on Windows (SYSTEM + Administrators only). Tests pass a temp dir.
    ///
    /// # Errors
    /// [`HelperError::Store`] if the directory cannot be created or locked down.
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self, HelperError> {
        let dir = dir.into();
        fs::create_dir_all(&dir)
            .map_err(|e| HelperError::Store(format!("create_dir_all {}: {e}", dir.display())))?;
        assert_restrictive_dacl(&dir)?;
        Ok(FileReceiptStore { dir })
    }

    fn snapshot_path(&self) -> PathBuf {
        self.dir.join(SNAPSHOT_FILE)
    }
}

impl ReceiptStore for FileReceiptStore {
    fn save(&self, state: &PersistedState) -> Result<(), HelperError> {
        let final_path = self.snapshot_path();
        let tmp_path = self.dir.join(format!("{SNAPSHOT_FILE}.tmp"));

        let mut body = Vec::new();
        ciborium::ser::into_writer(state, &mut body)
            .map_err(|e| HelperError::Store(format!("encode: {e}")))?;

        // Write to a temp file in the same dir, flush + fsync, then atomically
        // rename over the final path.
        {
            let mut f = fs::File::create(&tmp_path)
                .map_err(|e| HelperError::Store(format!("create tmp: {e}")))?;
            f.write_all(&body)
                .map_err(|e| HelperError::Store(format!("write tmp: {e}")))?;
            f.sync_all()
                .map_err(|e| HelperError::Store(format!("fsync tmp: {e}")))?;
        }
        atomic_replace(&tmp_path, &final_path)?;
        Ok(())
    }

    fn load(&self) -> Result<Option<PersistedState>, HelperError> {
        let path = self.snapshot_path();
        match fs::read(&path) {
            Ok(bytes) => {
                let state: PersistedState = ciborium::de::from_reader(&bytes[..])
                    .map_err(|e| HelperError::CorruptState(format!("decode: {e}")))?;
                if state.schema_version != SNAPSHOT_SCHEMA {
                    return Err(HelperError::CorruptState(format!(
                        "unknown schema version {}",
                        state.schema_version
                    )));
                }
                Ok(Some(state))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(HelperError::Store(format!("read {}: {e}", path.display()))),
        }
    }
}

/// Atomically replace `final_path` with `tmp_path`. On Unix `rename` replaces
/// atomically. On Windows `rename` fails if the destination exists, so we fall
/// back to remove-then-rename (a small non-atomic window). The fully-atomic
/// Windows path (`MoveFileEx(MOVEFILE_REPLACE_EXISTING)` / `ReplaceFileW`) is an
/// FFI call and belongs in the unsafe-isolated `ssk-winhost` crate — tracked as
/// a Windows-hardening follow-up; this crate stays `#![forbid(unsafe_code)]`.
fn atomic_replace(tmp_path: &Path, final_path: &Path) -> Result<(), HelperError> {
    match fs::rename(tmp_path, final_path) {
        Ok(()) => Ok(()),
        Err(_) if final_path.exists() => {
            fs::remove_file(final_path)
                .map_err(|e| HelperError::Store(format!("replace-remove: {e}")))?;
            fs::rename(tmp_path, final_path)
                .map_err(|e| HelperError::Store(format!("replace-rename: {e}")))
        }
        Err(e) => Err(HelperError::Store(format!("rename: {e}"))),
    }
}

/// Lock the store directory down to SYSTEM + Administrators on Windows via
/// `icacls` (no unsafe/FFI). A no-op elsewhere. Fail-closed: if the ACL cannot
/// be asserted, opening the store fails rather than leaving it world-readable.
#[cfg(windows)]
fn assert_restrictive_dacl(dir: &Path) -> Result<(), HelperError> {
    let status = std::process::Command::new("icacls")
        .arg(dir)
        .args([
            "/inheritance:r",
            "/grant:r",
            "SYSTEM:(OI)(CI)F",
            "/grant:r",
            "*S-1-5-32-544:(OI)(CI)F", // BUILTIN\Administrators, locale-independent SID
        ])
        .status()
        .map_err(|e| HelperError::Store(format!("icacls spawn: {e}")))?;
    if !status.success() {
        return Err(HelperError::Store(format!(
            "icacls failed to lock down {}: {status}",
            dir.display()
        )));
    }
    Ok(())
}

#[cfg(not(windows))]
fn assert_restrictive_dacl(_dir: &Path) -> Result<(), HelperError> {
    // No Windows ACLs off-Windows; the injected dir (tests) or POSIX perms
    // (deployment) govern. Documented as a no-op per SPEC §3.
    Ok(())
}
