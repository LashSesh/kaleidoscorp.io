#![forbid(unsafe_code)]

//! Bounded behavioral evidence, with no network or authorization capability.
//!
//! This baseline consumes caller-declared observations in one fixed, half-open
//! time window. It does not capture traffic, authenticate a process, learn from
//! live input, or grant connections. In particular, `NoAnomalyObserved` only
//! means none of the configured thresholds was exceeded in the supplied data.
//!
//! Reports identify their baseline, scope, provenance and expiry. All current
//! provenance variants are untrusted for enforcement. Deployment into the
//! daemon is deliberately deferred until trusted ingress and the policy seam
//! exist; see `docs/NETWORK_ANALYSIS_BASELINE.md`.

mod contract;
mod window;

pub mod replay;

pub use contract::{
    Baseline, BaselineConfig, ConfigError, Observation, Provenance, Scope, Signal, Transport,
    UnavailableReason, MAX_EVENTS, MAX_WINDOW_MS,
};
pub use window::{Assessment, Finding, Metrics, Verdict, WindowAnalyzer, FEATURE_SCHEMA};
