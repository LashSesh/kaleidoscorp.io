//! Error type for the privileged broker.

use ssk_boundary::BoundaryError;

/// Errors the broker can return from a privileged operation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
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
}
