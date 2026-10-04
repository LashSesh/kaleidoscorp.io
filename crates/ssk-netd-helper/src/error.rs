//! Error type for the privileged broker.

use ssk_boundary::BoundaryError;

use crate::store::Elevation;

/// Errors the broker can return from a privileged operation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum HelperError {
    /// The durable store could not be read or written.
    #[error("durable store error: {0}")]
    Store(String),
    /// A persisted snapshot failed to decode or was inconsistent.
    #[error("corrupt persisted state: {0}")]
    CorruptState(String),
    /// The underlying boundary operation failed.
    #[error("boundary error: {0}")]
    Boundary(#[from] BoundaryError),
    /// A privileged, system-mutating operation was attempted from a process
    /// that is not (or cannot be shown to be) elevated.
    ///
    /// The next step for an operator is *"re-run from an elevated
    /// (Administrator) shell"* — and, unlike the blanket hint the CLI appends
    /// to every winhost error today, this one is only emitted when elevation
    /// really is the problem, because it is a checked precondition rather than
    /// a guess. Machine code: `NOT_ELEVATED`.
    #[error("{operation} requires an elevated (Administrator) process (observed: {observed:?})")]
    NotElevated {
        operation: &'static str,
        observed: Elevation,
    },
}

impl HelperError {
    /// A stable machine-readable code for the CLI/IPC surface.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            HelperError::Store(_) => "STORE_ERROR",
            HelperError::CorruptState(_) => "CORRUPT_STATE",
            HelperError::Boundary(_) => "BOUNDARY_ERROR",
            HelperError::NotElevated { .. } => "NOT_ELEVATED",
        }
    }
}
