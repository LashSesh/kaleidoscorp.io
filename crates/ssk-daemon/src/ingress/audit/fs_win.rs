//! The Windows store. Until `C-WIN0` this refuses to open anything, so
//! `private_audit_store` is false and the ingress is unavailable on Windows
//! under either hardening mode; `C-WIN0` adds a std-only backend and `C-WIN3`
//! the ACL checks (design 6.4.9). Nothing here has run on Windows.

use std::path::PathBuf;

use super::fs::{LedgerFs, LedgerStore, StoreError};

#[derive(Debug, Clone)]
pub struct WindowsLedgerFs {
    #[allow(dead_code)]
    root: PathBuf,
}

impl WindowsLedgerFs {
    #[must_use]
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }
}

impl LedgerFs for WindowsLedgerFs {
    fn open_store(&self) -> Result<Box<dyn LedgerStore>, StoreError> {
        Err(StoreError::Unsupported)
    }

    fn is_private_store(&self) -> bool {
        false
    }

    fn read_key_file(&self) -> Result<Option<Vec<u8>>, StoreError> {
        Err(StoreError::Unsupported)
    }

    fn create_key_file(&self, _bytes: &[u8]) -> Result<(), StoreError> {
        Err(StoreError::Unsupported)
    }
}
