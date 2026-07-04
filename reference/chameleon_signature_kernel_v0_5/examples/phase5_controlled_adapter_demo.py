from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from chameleon_signature_kernel import (
    AuthorizationManifest,
    ChameleonKernel,
    ControlledAdapterFramework,
    ControlIntent,
    NormalizeTraceShapeOperator,
    BucketTimingOperator,
)
from chameleon_signature_kernel.adapters.trace_adapter import TraceAdapter
from chameleon_signature_kernel.corpus import ProfileCorpus


def build_objects():
    auth = AuthorizationManifest(
        source_name="phase5-local-fixture",
        owner_or_controller="local-developer",
        permission_basis="synthetic fixture for adapter operation planning",
    )
    records = [
        {
            "id": "r-001",
            "method": "GET",
            "url": "https://example.local/api/items",
            "status": 200,
            "headers": {"User-Agent": "ExampleClient/1.0", "Accept": "application/json"},
            "duration_ms": 122,
            "delta_ms": 45,
        },
        {
            "id": "r-002",
            "method": "GET",
            "url": "https://example.local/api/items/2",
            "status": 200,
            "headers": {"User-Agent": "ExampleClient/1.0", "Accept": "application/json"},
            "duration_ms": 161,
            "delta_ms": 80,
        },
    ]
    adapter = TraceAdapter(authorization=auth)
    return auth, adapter.from_records(records)


def main():
    auth, objects = build_objects()
    kernel = ChameleonKernel()
    signatures = [kernel.signature_for(obj) for obj in objects]
    corpus = ProfileCorpus()
    record = corpus.build_profile(
        name="local_api_trace",
        version="1.0.0",
        signatures=signatures,
        tags=("synthetic", "authorized", "adapter"),
        notes=("phase5 operational mask created from local fixtures",),
    )
    target = record.to_operational_mask(global_tolerance=0.70)

    framework = ControlledAdapterFramework(kernel=kernel)
    intent = ControlIntent(
        objective="authorized adapter operation for chameleon signature normalization",
        target_profile_name=target.name,
        mode="adapter_operation",
        export_level="operational_plan",
        notes=("network observations may be supplied by configured adapters",),
    )

    plan = framework.build_plan(
        intent=intent,
        objects=objects,
        operators=(NormalizeTraceShapeOperator(), BucketTimingOperator()),
        target=target,
        authorization=auth,
    )
    bundle = framework.export_bundle(plan)

    output_path = Path(__file__).resolve().parent / "phase5_controlled_adapter_export.json"
    bundle.write_json(output_path)

    print(f"plan_id={plan.plan_id[:12]}")
    print(f"overall_decision={plan.overall_decision}")
    print(f"decision_counts={plan.decision_counts()}")
    print(f"feedback_score={plan.feedback_score}")
    print(f"steps={len(plan.steps)}")
    print(f"unsupported={','.join(plan.blocked_capabilities)}")
    print(f"export={output_path}")


if __name__ == "__main__":
    main()
