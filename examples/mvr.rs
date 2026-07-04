use ssk_gates::GateVector;
use ssk_locator::LocatorPool;
use ssk_runtime::{sample_intent, Runtime};
use ssk_tensor::MemoryBackend;
use ssk_types::{Locator, LocatorId, LocatorType};

fn main() {
    let tensor = MemoryBackend::new();
    let runtime = Runtime {
        gate_vector: GateVector::with_all_default(),
        tensor: &tensor,
    };
    let pool = LocatorPool::new(vec![Locator {
        id: LocatorId::new("local"),
        locator_type: LocatorType::LocalOverlay,
        trusted: true,
        risk_score: 10,
    }]);

    let (outcome, _) = runtime
        .run_once(sample_intent(true), &pool)
        .expect("runtime should run");
    println!("{:?}", outcome.gate_report.outcome);
}
