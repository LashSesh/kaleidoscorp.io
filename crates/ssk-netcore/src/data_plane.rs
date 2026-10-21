#![forbid(unsafe_code)]

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use ssk_netadmin::admission::AdmissionToken;
use ssk_netadmin::route::RouteKind;

use crate::error::NetcoreError;
use crate::executor::RouteExecutor;
use crate::probe::ProbeReport;
use crate::session::EgressSession;

/// Mirrors `ssk_ipc::server::BoxFuture`'s shape so `Box<dyn DataPlane>` is
/// dyn-compatible across an async boundary, exactly like
/// `ssk_ipc::server::CommandHandler` already does.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The real, dyn-compatible replacement for `ssk-daemon`'s former
/// `MockDataPlane`: real health probing plus a real, held-open connect —
/// never a hardcoded boolean.
pub trait DataPlane: Send + Sync {
    /// Real health probe: connects, records the outcome, tears back down.
    fn probe_route<'a>(
        &'a self,
        route: &'a RouteKind,
        target: (&'a str, u16),
    ) -> BoxFuture<'a, ProbeReport>;

    /// Real, held-open connect: the returned session stays live until the
    /// caller shuts it down (the concrete mechanism behind `Active`/
    /// `Protected` state and a real kill-switch teardown).
    fn connect_route<'a>(
        &'a self,
        admission: AdmissionToken,
    ) -> BoxFuture<'a, Result<EgressSession, NetcoreError>>;

    /// Whether this data plane checks every address a `Direct` host name
    /// resolved to before dialling it. A caller that must not hand a client's
    /// name to an unchecked dial asks first. A data plane that cannot say (a
    /// test double, a plane that never resolves names itself) answers `false`.
    fn guards_direct_names(&self) -> bool {
        false
    }
}

/// The production `DataPlane`: every probe/connect is a real `RouteExecutor`
/// attempt.
pub struct NetcoreDataPlane {
    executor: Arc<RouteExecutor>,
}

impl NetcoreDataPlane {
    #[must_use]
    pub fn new(executor: Arc<RouteExecutor>) -> Self {
        Self { executor }
    }
}

impl DataPlane for NetcoreDataPlane {
    fn probe_route<'a>(
        &'a self,
        route: &'a RouteKind,
        target: (&'a str, u16),
    ) -> BoxFuture<'a, ProbeReport> {
        Box::pin(async move { self.executor.probe(route, target).await })
    }

    fn connect_route<'a>(
        &'a self,
        admission: AdmissionToken,
    ) -> BoxFuture<'a, Result<EgressSession, NetcoreError>> {
        Box::pin(async move {
            self.executor
                .connect(admission.route(), admission.target())
                .await
        })
    }

    fn guards_direct_names(&self) -> bool {
        self.executor.has_direct_guard()
    }
}
