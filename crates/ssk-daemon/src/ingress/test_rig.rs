//! The shared rig of the ingress tests: a control plane, a writer over the disk
//! double and an engine, wired as the host will wire them, with doubles for the
//! two seams of the data plane (resolver and connector), a scripted data plane and
//! a SOCKS5 proxy in memory. The tests of the engine and of the flow use it; the
//! doubles of the two netcore seams are the ones the integration tests share.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use ssk_config::ingress::{DestinationLogging, DirectAddressFamilies};
use ssk_config::routing::{
    AdapterTransport, RoutingAction, RoutingAdapter, RoutingConfig, RoutingProfile, RoutingRule,
};
use ssk_netadmin::admission::AdmissionToken;
use ssk_netadmin::audit::summarise_route;
use ssk_netadmin::RouteKind;
use ssk_netcore::{
    BoxFuture, Connected, DataPlane, EgressSession, NameResolver, NetcoreDataPlane, NetcoreError,
    ProbeReport, TcpConnector,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

use super::audit::dest::{DestKey, DestSealer};
use super::audit::record::FlowAuditEvent;
use super::audit::testing::FakeIo;
use super::audit::writer::{
    system_clock, AuditOpenCfg, FlowAuditWriter, Replayed, TripFn, SUMMARY_FLOOR,
};
use super::engine::{decide, open_tunnel, Admitted, Denied, DialFault, EngineCtx, Established};
use super::guard::{build_ingress_executor, GuardCells, IngressDirectGuard};
use super::shared::{IngressShared, Installed};
use super::target::{canonicalize, RawTarget};
use super::types::{
    lock_unpoisoned, Actor, ClientLabel, Controls, GateMode, IngressCfgView, PeerStamp,
    ResultOutcome, SystemClock, TripReason, Tuning,
};
use crate::routing::ConfiguredRouting;

// The doubles of the two netcore seams (shared with the integration tests).
include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/support/net_fakes.rs"
));

pub(crate) const LISTENER: &str = "127.0.0.1:10800";
pub(crate) const PUBLIC: &str = "93.184.216.34";
pub(crate) const OTHER: &str = "1.1.1.1";
pub(crate) const PROXY: &str = "198.51.100.7";

pub(crate) fn sa(text: &str) -> SocketAddr {
    text.parse().expect("test address")
}

// -- configuration ----------------------------------------------------------

pub(crate) fn rule(
    id: &str,
    priority: u32,
    destination: Option<&str>,
    suffix: Option<&str>,
    port: Option<u16>,
    action: RoutingAction,
) -> RoutingRule {
    RoutingRule {
        id: id.into(),
        priority,
        destination: destination.map(str::to_owned),
        domain_suffix: suffix.map(str::to_owned),
        port,
        action,
        require_attestation: false,
    }
}

pub(crate) fn adapter(id: &str, transport: AdapterTransport) -> RoutingAdapter {
    RoutingAdapter {
        id: id.into(),
        transport,
    }
}

pub(crate) fn socks(host: &str, port: u16) -> AdapterTransport {
    AdapterTransport::Socks5 {
        host: host.into(),
        port,
    }
}

pub(crate) fn adapter_action(id: &str) -> RoutingAction {
    RoutingAction::Adapter {
        adapter_id: id.into(),
    }
}

/// The rules most tests share: two exact allows, a suffix allow for names and a
/// deny.
pub(crate) fn standard_rules() -> Vec<RoutingRule> {
    vec![
        rule(
            "allow-web",
            10,
            Some(PUBLIC),
            None,
            Some(443),
            RoutingAction::Direct,
        ),
        rule(
            "allow-names",
            20,
            None,
            Some("example.test"),
            None,
            RoutingAction::Direct,
        ),
        rule(
            "deny-other",
            30,
            Some(OTHER),
            None,
            None,
            RoutingAction::Deny,
        ),
    ]
}

pub(crate) fn routing_of(
    rules: Vec<RoutingRule>,
    adapters: Vec<RoutingAdapter>,
) -> ConfiguredRouting {
    ConfiguredRouting::new(&RoutingConfig {
        default_profile: "main".into(),
        profiles: vec![RoutingProfile {
            id: "main".into(),
            name: "main".into(),
            rules,
        }],
        adapters,
    })
}

// -- the data plane double ---------------------------------------------------

pub(crate) type Maker = Arc<dyn Fn() -> NetcoreError + Send + Sync>;

pub(crate) enum Script {
    /// The real executor.
    Delegate,
    Fail(Maker),
    /// Never completes; the drop of the future is counted.
    Hang,
}

pub(crate) struct DropCount(Arc<AtomicUsize>);

impl Drop for DropCount {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

/// `(route summary, host, port)` of every `connect_route` call.
pub(crate) type Call = (String, String, u16);

pub(crate) struct TestPlane {
    pub(crate) inner: Option<NetcoreDataPlane>,
    pub(crate) script: Mutex<Script>,
    pub(crate) guards_names: AtomicBool,
    pub(crate) calls: Mutex<Vec<Call>>,
    pub(crate) hung: AtomicUsize,
    pub(crate) hung_dropped: Arc<AtomicUsize>,
    /// When set, the gate is disarmed the moment a real dial has completed.
    pub(crate) mover: Mutex<Option<Arc<IngressShared>>>,
    /// Called, if set, when a dial starts: a test uses it to hold the disk at
    /// exactly that point.
    pub(crate) on_dial: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}

impl TestPlane {
    pub(crate) fn new(inner: Option<NetcoreDataPlane>, script: Script, guards: bool) -> Arc<Self> {
        Arc::new(Self {
            inner,
            script: Mutex::new(script),
            guards_names: AtomicBool::new(guards),
            calls: Mutex::new(Vec::new()),
            hung: AtomicUsize::new(0),
            hung_dropped: Arc::new(AtomicUsize::new(0)),
            mover: Mutex::new(None),
            on_dial: Mutex::new(None),
        })
    }

    pub(crate) fn calls(&self) -> Vec<Call> {
        lock_unpoisoned(&self.calls).clone()
    }
}

impl DataPlane for TestPlane {
    fn probe_route<'a>(
        &'a self,
        _route: &'a RouteKind,
        _target: (&'a str, u16),
    ) -> BoxFuture<'a, ProbeReport> {
        panic!("the ingress never probes");
    }

    fn connect_route<'a>(
        &'a self,
        admission: AdmissionToken,
    ) -> BoxFuture<'a, Result<EgressSession, NetcoreError>> {
        let (host, port) = admission.target();
        lock_unpoisoned(&self.calls).push((
            summarise_route(admission.route()),
            host.to_owned(),
            port,
        ));
        let hook = lock_unpoisoned(&self.on_dial).clone();
        if let Some(hook) = hook {
            hook();
        }
        let step = match &*lock_unpoisoned(&self.script) {
            Script::Delegate => 0,
            Script::Fail(_) => 1,
            Script::Hang => 2,
        };
        match step {
            0 => {
                let real = self
                    .inner
                    .as_ref()
                    .expect("a real data plane")
                    .connect_route(admission);
                match lock_unpoisoned(&self.mover).clone() {
                    None => real,
                    // The dial completes and, in the same poll, the gate moves:
                    // the engine's own look after the dial is what must catch it.
                    Some(shared) => Box::pin(async move {
                        let session = real.await;
                        shared.cas(None, |mode| {
                            matches!(mode, GateMode::Armed { .. }).then_some(GateMode::Disarmed)
                        });
                        session
                    }),
                }
            }
            1 => {
                let error = match &*lock_unpoisoned(&self.script) {
                    Script::Fail(maker) => maker(),
                    _ => unreachable!("checked above"),
                };
                Box::pin(async move { Err(error) })
            }
            _ => {
                self.hung.fetch_add(1, Ordering::SeqCst);
                let guard = DropCount(Arc::clone(&self.hung_dropped));
                Box::pin(async move {
                    let _guard = guard;
                    std::future::pending::<()>().await;
                    Err(NetcoreError::ResolverBusy)
                })
            }
        }
    }

    fn guards_direct_names(&self) -> bool {
        self.guards_names.load(Ordering::SeqCst)
    }
}

// -- a SOCKS5 proxy in memory --------------------------------------------------

/// A `TcpConnector` whose only reachable address is a SOCKS5 proxy that
/// accepts any CONNECT and records `(ATYP, host, port)`.
pub(crate) struct FakeProxy {
    pub(crate) address: SocketAddr,
    pub(crate) requests: Arc<Mutex<Vec<(u8, String, u16)>>>,
    pub(crate) started: Mutex<Vec<SocketAddr>>,
}

impl FakeProxy {
    pub(crate) fn new(address: &str) -> Arc<Self> {
        Arc::new(Self {
            address: sa(address),
            requests: Arc::new(Mutex::new(Vec::new())),
            started: Mutex::new(Vec::new()),
        })
    }

    pub(crate) fn requests(&self) -> Vec<(u8, String, u16)> {
        lock_unpoisoned(&self.requests).clone()
    }

    pub(crate) fn started(&self) -> Vec<SocketAddr> {
        lock_unpoisoned(&self.started).clone()
    }
}

pub(crate) async fn serve_socks(
    mut stream: DuplexStream,
    requests: Arc<Mutex<Vec<(u8, String, u16)>>>,
) {
    let mut head = [0u8; 2];
    if stream.read_exact(&mut head).await.is_err() {
        return;
    }
    let mut methods = vec![0u8; usize::from(head[1])];
    if stream.read_exact(&mut methods).await.is_err() {
        return;
    }
    if stream.write_all(&[5, 0]).await.is_err() {
        return;
    }
    let mut request = [0u8; 4];
    if stream.read_exact(&mut request).await.is_err() {
        return;
    }
    let host = match request[3] {
        1 => {
            let mut octets = [0u8; 4];
            let _ = stream.read_exact(&mut octets).await;
            std::net::Ipv4Addr::from(octets).to_string()
        }
        3 => {
            let mut length = [0u8; 1];
            let _ = stream.read_exact(&mut length).await;
            let mut name = vec![0u8; usize::from(length[0])];
            let _ = stream.read_exact(&mut name).await;
            String::from_utf8_lossy(&name).into_owned()
        }
        _ => {
            let mut octets = [0u8; 16];
            let _ = stream.read_exact(&mut octets).await;
            std::net::Ipv6Addr::from(octets).to_string()
        }
    };
    let mut port = [0u8; 2];
    let _ = stream.read_exact(&mut port).await;
    lock_unpoisoned(&requests).push((request[3], host, u16::from_be_bytes(port)));
    let _ = stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await;
    let mut sink = [0u8; 64];
    while stream.read(&mut sink).await.is_ok_and(|n| n > 0) {}
}

impl TcpConnector for FakeProxy {
    fn connect<'a>(&'a self, addr: SocketAddr) -> BoxFuture<'a, io::Result<Connected>> {
        lock_unpoisoned(&self.started).push(addr);
        let reachable = addr == self.address;
        let requests = Arc::clone(&self.requests);
        Box::pin(async move {
            if !reachable {
                return Err(io::Error::from(io::ErrorKind::ConnectionRefused));
            }
            let (ours, theirs) = tokio::io::duplex(4096);
            tokio::spawn(serve_socks(theirs, requests));
            Ok(Connected {
                transport: Box::new(ours),
                local_addr: Some(net_fakes::scripted_local_addr()),
            })
        })
    }
}

/// A connector that keeps the far end of every connection it makes, so that a
/// test can see when the engine closed the near end.
pub(crate) struct KeepingConnector {
    pub(crate) far: Mutex<Vec<DuplexStream>>,
    pub(crate) started: Mutex<Vec<SocketAddr>>,
}

impl KeepingConnector {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            far: Mutex::new(Vec::new()),
            started: Mutex::new(Vec::new()),
        })
    }

    pub(crate) fn take_far(&self) -> DuplexStream {
        lock_unpoisoned(&self.far).remove(0)
    }
}

impl TcpConnector for KeepingConnector {
    fn connect<'a>(&'a self, addr: SocketAddr) -> BoxFuture<'a, io::Result<Connected>> {
        lock_unpoisoned(&self.started).push(addr);
        let (ours, theirs) = tokio::io::duplex(4096);
        lock_unpoisoned(&self.far).push(theirs);
        Box::pin(async move {
            Ok(Connected {
                transport: Box::new(ours),
                local_addr: Some(net_fakes::scripted_local_addr()),
            })
        })
    }
}

/// A resolver that answers only after it is released, so that a lookup can be
/// held while something else happens.
pub(crate) struct GatedResolver {
    pub(crate) state: Mutex<(bool, bool)>,
    pub(crate) changed: Condvar,
    pub(crate) answer: Vec<std::net::IpAddr>,
}

impl GatedResolver {
    pub(crate) fn new(answer: &str) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new((false, false)),
            changed: Condvar::new(),
            answer: vec![answer.parse().expect("test address")],
        })
    }

    pub(crate) fn entered(&self) -> bool {
        lock_unpoisoned(&self.state).0
    }

    pub(crate) fn release(&self) {
        lock_unpoisoned(&self.state).1 = true;
        self.changed.notify_all();
    }
}

impl NameResolver for GatedResolver {
    fn resolve(&self, _name: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        let mut state = lock_unpoisoned(&self.state);
        state.0 = true;
        while !state.1 {
            state = self
                .changed
                .wait(state)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        Ok(self
            .answer
            .iter()
            .map(|ip| SocketAddr::new(*ip, port))
            .collect())
    }
}

// -- the rig -------------------------------------------------------------------

pub(crate) struct Spec {
    pub(crate) rules: Vec<RoutingRule>,
    pub(crate) adapters: Vec<RoutingAdapter>,
    pub(crate) families: DirectAddressFamilies,
    pub(crate) tuning: Tuning,
    pub(crate) connect_timeout_ms: u32,
    pub(crate) logging: DestinationLogging,
    pub(crate) script: Script,
    /// The real executor's resolver and connector, when the script delegates.
    pub(crate) net: Option<(Arc<dyn NameResolver>, Arc<dyn TcpConnector>)>,
    pub(crate) guards_names: bool,
}

impl Spec {
    pub(crate) fn new() -> Self {
        Self {
            rules: standard_rules(),
            adapters: vec![adapter("exit", socks(PROXY, 1080))],
            families: DirectAddressFamilies::Ipv4Only,
            tuning: Tuning::default(),
            connect_timeout_ms: 2_000,
            logging: DestinationLogging::Plain,
            script: Script::Delegate,
            net: None,
            guards_names: true,
        }
    }

    pub(crate) fn fails_with(
        mut self,
        maker: impl Fn() -> NetcoreError + Send + Sync + 'static,
    ) -> Self {
        self.script = Script::Fail(Arc::new(maker));
        self
    }

    pub(crate) fn hangs(mut self) -> Self {
        self.script = Script::Hang;
        self
    }

    pub(crate) fn over(
        mut self,
        resolver: Arc<dyn NameResolver>,
        connector: Arc<dyn TcpConnector>,
    ) -> Self {
        self.script = Script::Delegate;
        self.net = Some((resolver, connector));
        self
    }
}

pub(crate) struct Rig {
    pub(crate) ctx: EngineCtx,
    pub(crate) shared: Arc<IngressShared>,
    pub(crate) io: FakeIo,
    pub(crate) trips: Arc<Mutex<Vec<TripReason>>>,
    pub(crate) plane: Arc<TestPlane>,
}

pub(crate) fn operator() -> Actor {
    Actor::Operator {
        peer: Some(Arc::from("uid:1000")),
        client: ClientLabel::Cli,
    }
}

pub(crate) fn open_cfg(logging: DestinationLogging) -> AuditOpenCfg {
    AuditOpenCfg {
        segment_bytes: 1 << 20,
        retain_segments: 4,
        denied_share_percent: 20,
        summary_share_percent: 5,
        destination_logging: logging,
        fingerprint: IngressCfgView::for_tests().fingerprint,
        daemon_version: "0.0.0-test".to_owned(),
        queue_cap: 256,
        summary_floor: SUMMARY_FLOOR,
        clock: system_clock(),
    }
}

pub(crate) fn sealer_of(logging: DestinationLogging) -> DestSealer {
    match logging {
        DestinationLogging::Plain => DestSealer::Plain,
        DestinationLogging::Hashed => DestSealer::Hashed(Arc::new(DestKey::from_bytes([5; 32]))),
    }
}

impl Rig {
    pub(crate) async fn new(spec: Spec) -> Self {
        let mut cfg = IngressCfgView::for_tests();
        cfg.families = spec.families;
        cfg.limits.connect_timeout_ms = spec.connect_timeout_ms;
        cfg.destination_logging = spec.logging;
        let (events, _) = tokio::sync::broadcast::channel(16);
        let shared = IngressShared::new(cfg.clone(), spec.tuning.clone(), events);
        let routing = Arc::new(routing_of(spec.rules, spec.adapters));

        // The writer, over the disk double; a write fault trips the gate.
        let io = FakeIo::new();
        let trips: Arc<Mutex<Vec<TripReason>>> = Arc::new(Mutex::new(Vec::new()));
        let on_trip: TripFn = {
            let shared = Arc::clone(&shared);
            let trips = Arc::clone(&trips);
            Arc::new(move |reason| {
                lock_unpoisoned(&trips).push(reason);
                shared.trip(reason);
            })
        };
        let writer = FlowAuditWriter::open_with(
            io.clone(),
            Replayed::fresh(),
            &open_cfg(spec.logging),
            sealer_of(spec.logging),
            on_trip,
        )
        .expect("opens");
        let boot: Arc<str> = Arc::from(format!("b{}", writer.boot_seq()));
        shared.ledger_slot().install(Installed {
            writer: Arc::new(writer),
            boot,
        });

        // The data plane: the real executor, guarded as the daemon builds it.
        let cells = GuardCells::new();
        cells.set_listener(match sa(LISTENER) {
            SocketAddr::V4(v4) => v4,
            SocketAddr::V6(_) => unreachable!("the test listener is IPv4"),
        });
        assert!(cells.set_gate(shared.gate()));
        let inner = spec.net.map(|(resolver, connector)| {
            let guard = IngressDirectGuard::from_routing(cells, &routing, ["main"]);
            let executor = build_ingress_executor(routing.adapters.clone(), &cfg, Arc::new(guard))
                .with_resolver(resolver)
                .with_connector(connector);
            NetcoreDataPlane::new(Arc::new(executor))
        });
        let guards = spec.guards_names;
        let plane = TestPlane::new(inner, spec.script, guards);
        let data_plane: Arc<dyn DataPlane> = plane.clone();
        let ctx = EngineCtx::new(
            routing,
            data_plane,
            Arc::clone(&shared),
            sa(LISTENER),
            Arc::new(SystemClock),
        );

        shared.update_host_facts(|facts| {
            facts.accept_alive = true;
            facts.controls = Controls {
                exclusive_bind: true,
                peer_check: true,
                private_audit_store: true,
            };
            facts.listen = Some(sa(LISTENER));
        });
        assert!(shared.start_transition(0, GateMode::Disarmed).is_some());
        shared.arm("main", operator()).await.expect("armed");
        Self {
            ctx,
            shared,
            io,
            trips,
            plane,
        }
    }

    pub(crate) fn epoch(&self) -> u64 {
        self.shared.gate().borrow().epoch
    }

    pub(crate) fn peer() -> PeerStamp {
        PeerStamp {
            peer: Arc::from("127.0.0.1:50000"),
            verified: true,
        }
    }

    /// `decide` for a name or an address as a front end would call it.
    pub(crate) fn admit(&self, raw: RawTarget) -> Result<Admitted, Denied> {
        let target = canonicalize(raw).expect("canonical");
        let id = self.ctx.mint_flow_id().expect("a writer is installed");
        decide(&self.ctx, "main", self.epoch(), id, &target)
    }

    pub(crate) fn admit_name(&self, name: &str, port: u16) -> Result<Admitted, Denied> {
        self.admit(RawTarget::Name(name.as_bytes().to_vec(), port))
    }

    pub(crate) fn admit_v4(&self, ip: &str, port: u16) -> Result<Admitted, Denied> {
        match ip.parse::<std::net::IpAddr>().expect("address") {
            std::net::IpAddr::V4(v4) => self.admit(RawTarget::V4(v4, port)),
            std::net::IpAddr::V6(v6) => self.admit(RawTarget::V6(v6, port)),
        }
    }

    pub(crate) async fn open(&self, adm: Admitted) -> Result<Established, DialFault> {
        let mut gate = self.shared.gate();
        open_tunnel(&self.ctx, adm, &Self::peer(), "main", &mut gate).await
    }

    /// Every record on the disk, oldest first.
    pub(crate) fn events(&self) -> Vec<FlowAuditEvent> {
        self.io.records().into_iter().map(|r| r.event).collect()
    }

    pub(crate) fn results(&self) -> Vec<(ResultOutcome, Option<String>)> {
        self.events()
            .into_iter()
            .filter_map(|event| match event {
                FlowAuditEvent::Result {
                    outcome,
                    error_code,
                    ..
                } => Some((outcome, error_code)),
                _ => None,
            })
            .collect()
    }

    pub(crate) fn count(&self, kind: &str) -> usize {
        self.events().iter().filter(|e| e.kind() == kind).count()
    }

    /// Waits (real time) until `done` holds of the disk, for records that are
    /// written by a compensation and not awaited by anyone.
    pub(crate) async fn until(&self, what: &str, done: impl Fn(&Rig) -> bool) {
        for _ in 0..500 {
            if done(self) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("timed out waiting for {what}: {:?}", self.events());
    }

    pub(crate) async fn wait_in_sync(&self) {
        for _ in 0..500 {
            if self.io.with(|d| d.in_sync) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("the writer never reached its sync");
    }
}
