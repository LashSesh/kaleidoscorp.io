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
//! IMDF-B adds the [`Wavefront`], [`BirefringentSplit`]/[`Parallax`], the
//! [`QLogicGate`] (`gate_vector_is_not_single_score`), and [`FourPiClosure`]
//! (`four_pi_requires_second_orientation_pass`). IMDF-C adds the [`RunDescriptor`]
//! with [`ImdfReplayManifest`] (`replay_manifest_contains_all_inputs`),
//! [`reanalyze`] (`reanalysis_recovers_self_anchor`), and the hash-chained
//! [`SelfPerceptionAtlas`] (`audit_ledger_is_append_only`) — the Dome's main
//! artifact, which the SSCL Crown's Mirror-Dome feed and the FCHL field layer
//! consume.

pub mod aperture;
pub mod atlas;
pub mod claim;
pub mod closure;
pub mod contact;
pub mod error;
pub mod observer;
pub mod qlogic;
pub mod replay;
pub mod self_anchor;
pub mod wavefront;

pub use aperture::{Aperture, ApertureSession, FocusResult, Reading};
pub use atlas::{AtlasEntry, AtlasObservation, SelfPerceptionAtlas};
pub use claim::{Claim, ClaimClass, ClaimError, ClaimLedger, ResidueDisposition};
pub use closure::{ClosureReport, ClosureState, FourPiClosure, Orientation, OrientationPass};
pub use contact::{Contact, ContactGapReason, Kontaktluecke};
pub use error::ImdfError;
pub use observer::{
    Blindspot, Lens, ObserverId, ObserverModel, TrustLevel, Vantage, SELF_OBSERVATION_USE,
};
pub use qlogic::{
    QAxis, QLogicGate, QLogicInput, QLogicThresholds, QLogicVector, QOutcome, QState,
};
pub use replay::{
    reanalyze, ImdfReplayManifest, ReanalysisReport, ReanalysisVerdict, RunDescriptor,
    RunTransition, StabilityCertificate,
};
pub use self_anchor::{
    BcikCrossing, DomeLocator, LocatorAddressId, NullAnchor, SelfAnchor, SelfAnchorId,
};
pub use wavefront::{BirefringentSplit, Parallax, Ray, RaySet, SplitAxis, Wavefront};
