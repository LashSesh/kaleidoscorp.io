//! Error type for the Mirror Dome layer.

/// Errors the IMDF layer can return.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ImdfError {
    /// An observer was constructed without valid self-observation authorization.
    #[error("observer requires valid self-observation authorization")]
    Unauthorized,
    /// A focus was attempted before an aperture was opened (Focus ⇒ ∃A).
    #[error("aperture required before focus")]
    ApertureRequired,
    /// A closure was queried before its second orientation pass completed.
    #[error("4π closure requires a second orientation pass")]
    ClosureIncomplete,
    /// A replay manifest was missing one of its committed inputs.
    #[error("replay manifest is missing input: {0}")]
    ReplayInputMissing(String),
    /// Two observers in an `ObserverField` shared an identity (distinctness
    /// invariant violated).
    #[error("observer field requires distinct observers")]
    DuplicateObserver,
    /// A k-way parallax was requested over fewer than two observers (A3).
    #[error("parallax is underdetermined: fewer than two observers")]
    ParallaxUnderdetermined,
    /// A serialization error from the content-address layer.
    #[error("types error: {0}")]
    Types(String),
}

impl From<ssk_types::TypeError> for ImdfError {
    fn from(e: ssk_types::TypeError) -> Self {
        ImdfError::Types(e.to_string())
    }
}
