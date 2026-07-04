#![forbid(unsafe_code)]

//! # ssk-imdf — the Immersive Mirror Dome Field layer (IMDF-0..2 seed)
//!
//! The Mirror Dome is the system's **self-perception** layer: it observes the
//! system's own surfaces (spectra from `ssk-signature`) through authorized
//! observers and commits what it perceives to a hash-chained atlas. It sits on
//! the Ω kernel and reuses its content-address primitives (`ssk_types`), never
//! duplicating them.
//!
//! This crate implements the seed rungs (IMDF-0..2), each held to the exact
//! acceptance tests in IMDF Appendix A:
//!
//! * [`SelfAnchor`] — canonical own-identity, domain-separated from a
//!   [`DomeLocator`] so identity is never a location (`self_anchor_is_not_locator`).
//! * [`ObserverModel`] — an authorized self-perspective; unauthorized construction
//!   is impossible (`observer_without_authorization_fails`).
//! * [`Aperture`] / [`ApertureSession`] — aperture-before-focus (Focus ⇒ ∃A,
//!   `aperture_before_focus_required`); a surface outside the aperture becomes a
//!   residue (`hidden_surface_becomes_residue`); a blindspot reads blind, never a
//!   fact (`blindspot_is_not_reported_as_fact`).
//!
//! IMDF-B (wavefront / birefringent split / parallax / QLOGIC gate / 4π-closure)
//! and IMDF-C (run descriptor / replay manifest / reanalysis / SelfPerceptionAtlas)
//! build on this base.

pub mod aperture;
pub mod closure;
pub mod error;
pub mod observer;
pub mod qlogic;
pub mod self_anchor;
pub mod wavefront;

pub use aperture::{Aperture, ApertureSession, FocusResult, Reading};
pub use closure::{ClosureState, FourPiClosure, OrientationPass};
pub use error::ImdfError;
pub use observer::{
    Blindspot, Lens, ObserverId, ObserverModel, TrustLevel, Vantage, SELF_OBSERVATION_USE,
};
pub use qlogic::{QAxis, QLogicGate, QLogicInput, QLogicThresholds, QLogicVector, QOutcome};
pub use self_anchor::{BcikCrossing, DomeLocator, LocatorAddressId, SelfAnchor, SelfAnchorId};
pub use wavefront::{BirefringentSplit, Parallax, Wavefront};
