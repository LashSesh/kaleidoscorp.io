use ssk_gates::GateVector;
use ssk_locator::StaticLocatorPool;
use ssk_runtime::{sample_intent, DeterminismContext, Runtime};
use ssk_tensor::MemoryBackend;
use ssk_types::{
    digest_of, CostClass, EndpointRef, EpochId, HashAlg, HealthStatus, LocatorFacet, LocatorId,
    LocatorKind, RiskClass, TraceId, TrustClass, Ttl,
};

fn pool() -> StaticLocatorPool {
    StaticLocatorPool::new(vec![LocatorFacet {
        id: LocatorId::new("local"),
        kind: LocatorKind::LocalOverlay,
        endpoint: EndpointRef::new("local-endpoint"),
        route: ssk_types::RouteClass::Direct,
        transport: ssk_types::TransportClass::Tcp,
        epoch: EpochId(0),
        ttl: Ttl(100),
        trust: TrustClass::Owned,
        cost: CostClass::Free,
        risk: RiskClass::Low,
        health: HealthStatus::Live,
        trace: TraceId::new("trace-local"),
        trusted: true,
        risk_score: 10,
    }])
}

#[test]
fn deterministic_regression_multi_context() {
    let contexts = [
        DeterminismContext {
            seeded: false,
            epoch: 0,
        },
        DeterminismContext {
            seeded: true,
            epoch: 1,
        },
        DeterminismContext {
            seeded: true,
            epoch: 42,
        },
    ];

    for ctx in contexts {
        let tensor_a = MemoryBackend::new();
        let tensor_b = MemoryBackend::new();
        let runtime_a = Runtime {
            gate_vector: GateVector::with_all_default(),
            tensor: &tensor_a,
        };
        let runtime_b = Runtime {
            gate_vector: GateVector::with_all_default(),
            tensor: &tensor_b,
        };

        let (a, ma) = runtime_a
            .run_once_with_context(sample_intent(true), &pool(), &ctx)
            .expect("run a");
        let (b, mb) = runtime_b
            .run_once_with_context(sample_intent(true), &pool(), &ctx)
            .expect("run b");

        let ad = digest_of(&a, HashAlg::Blake3).expect("digest a");
        let bd = digest_of(&b, HashAlg::Blake3).expect("digest b");

        assert_eq!(ad, bd);
        assert_eq!(ma.trace_head, mb.trace_head);
        assert_eq!(ma.descriptor.scheduler, mb.descriptor.scheduler);
    }
}
