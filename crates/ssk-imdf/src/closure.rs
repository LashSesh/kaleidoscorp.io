//! 4π-Closure (IMDF 11) — orientation return.
//!
//! A single 2π orientation pass is not enough to establish closure: like a
//! spinor, one full turn returns to a sign-flipped state, and only a *second*
//! consistent pass (4π total) returns to identity. A [`FourPiClosure`] is
//! therefore `Open` until two orientation passes agree; a lone pass, or two
//! passes that disagree, leaves it open.

use serde::{Deserialize, Serialize};
use ssk_types::Digest;

use crate::error::ImdfError;

/// One recorded orientation observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrientationPass {
    pub digest: Digest,
}

impl OrientationPass {
    #[must_use]
    pub fn new(digest: Digest) -> Self {
        OrientationPass { digest }
    }
}

/// Whether orientation has returned to identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClosureState {
    Open,
    Closed,
}

/// Accumulates orientation passes; closes only on a consistent second pass.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FourPiClosure {
    passes: Vec<OrientationPass>,
}

impl FourPiClosure {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an orientation pass.
    pub fn record_pass(&mut self, pass: OrientationPass) {
        self.passes.push(pass);
    }

    #[must_use]
    pub fn pass_count(&self) -> usize {
        self.passes.len()
    }

    /// Closed iff at least two passes have been recorded and the first two agree
    /// (orientation returned to its starting state — 4π, not 2π).
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.passes.len() >= 2 && self.passes[0].digest == self.passes[1].digest
    }

    #[must_use]
    pub fn state(&self) -> ClosureState {
        if self.is_closed() {
            ClosureState::Closed
        } else {
            ClosureState::Open
        }
    }

    /// Require closure.
    ///
    /// # Errors
    /// [`ImdfError::ClosureIncomplete`] if fewer than two consistent passes.
    pub fn require_closed(&self) -> Result<(), ImdfError> {
        if self.is_closed() {
            Ok(())
        } else {
            Err(ImdfError::ClosureIncomplete)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssk_types::{digest_of, HashAlg};

    fn orientation(tag: &str) -> OrientationPass {
        OrientationPass::new(digest_of(&tag, HashAlg::Blake3).unwrap())
    }

    // IMDF Appendix A: four_pi_requires_second_orientation_pass.
    #[test]
    fn four_pi_requires_second_orientation_pass() {
        let mut closure = FourPiClosure::new();
        // No pass: open.
        assert_eq!(closure.state(), ClosureState::Open);
        assert_eq!(
            closure.require_closed().unwrap_err(),
            ImdfError::ClosureIncomplete
        );

        // One 2π pass is NOT enough.
        closure.record_pass(orientation("north"));
        assert!(!closure.is_closed());
        assert_eq!(
            closure.require_closed().unwrap_err(),
            ImdfError::ClosureIncomplete
        );

        // A consistent second pass (4π) closes it.
        closure.record_pass(orientation("north"));
        assert!(closure.is_closed());
        assert_eq!(closure.state(), ClosureState::Closed);
        assert!(closure.require_closed().is_ok());
    }

    #[test]
    fn inconsistent_second_pass_does_not_close() {
        let mut closure = FourPiClosure::new();
        closure.record_pass(orientation("north"));
        closure.record_pass(orientation("south"));
        assert!(
            !closure.is_closed(),
            "a disagreeing second pass leaves orientation open"
        );
    }
}
