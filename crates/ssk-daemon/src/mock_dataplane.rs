#![forbid(unsafe_code)]

//! Stand-in for `ssk-netcore::RouteExecutor` (Phase 3). Lets
//! `activate_profile`/`deactivate` exercise real daemon state transitions and
//! IPC contract behavior now — the daemon and protocol are exercised for
//! real; only route/adapter viability itself is simulated until the real
//! data plane ships.

pub trait MockDataPlane: Send + Sync {
    fn route_available(&self, profile_id: &str) -> bool;
}

/// A data plane that always reports a viable route — used to exercise the
/// `Inactive -> Activating -> Protected` happy path.
pub struct AlwaysUpMockDataPlane;

impl MockDataPlane for AlwaysUpMockDataPlane {
    fn route_available(&self, _profile_id: &str) -> bool {
        true
    }
}

/// A data plane that never has a viable route — used to exercise the
/// fail-closed `Inactive -> Activating -> FailClosed` path.
pub struct AlwaysDownMockDataPlane;

impl MockDataPlane for AlwaysDownMockDataPlane {
    fn route_available(&self, _profile_id: &str) -> bool {
        false
    }
}
