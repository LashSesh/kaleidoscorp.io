//! Separate, held-only VPN control domain. No tunnel release or network authority.
//! The host supplies authenticated peers, protected policy/journal and a backend.
mod broker;
pub mod client;
pub mod configuration;
pub mod journal;
mod policy;
pub mod protocol;

pub use broker::{Backend, Broker, LiveSession, Observation, PrepareError, Service};
pub use policy::Policy;
pub use protocol::{
    Command, Failure, Phase, ProcessIdentity, RecoveryEvidence, RecoveryFailure, Reject, Request,
    Response, Status, Verb,
};

#[cfg(test)]
mod tests;
