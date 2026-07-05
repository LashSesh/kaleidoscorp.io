from pathlib import Path
import tempfile
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from chameleon_signature_kernel import (
    AuthorizationManifest,
    BucketTimingOperator,
    ChameleonKernel,
    NormalizeTraceShapeOperator,
    RedactIdentifierFieldsOperator,
    TargetProfile,
)
from chameleon_signature_kernel.adapters import TraceAdapter
from chameleon_signature_kernel.audit_ledger import AuditLedger


def main() -> None:
    authorization = AuthorizationManifest(
        source_name="local-demo-trace",
        owner_or_controller="developer-owned-lab",
        permission_basis="self-owned synthetic trace for adapter analysis",
        allowed_uses=("offline_analysis", "offline_redaction", "adapter_operation"),
        evidence_ref="demo://synthetic",
    )

    records = [
        {
            "protocol": "http",
            "method": "GET",
            "url": "https://example.test/api/status",
            "headers": {"User-Agent": "DemoClient/1.0", "Authorization": "Bearer local-demo"},
            "status": 200,
            "client_ip": "192.0.2.10",
            "interarrival_ms": 125,
            "jitter_ms": 18,
        },
        {
            "protocol": "http",
            "method": "GET",
            "url": "https://example.test/api/status",
            "headers": {"User-Agent": "DemoClient/1.0"},
            "status": 200,
            "interarrival_ms": 138,
            "jitter_ms": 22,
        },
    ]

    adapter = TraceAdapter(authorization)
    objects = adapter.from_records(records)
    kernel = ChameleonKernel()

    analysis_target = TargetProfile(
        name="demo-sensitive-source-shape",
        signature=kernel.signature_for(objects[0]),
        dimension_tolerances={
            "shape": 0.30,
            "ordering": 0.40,
            "entropy": 0.80,
            "timing": 0.80,
            "semantic": 0.30,
            "linkability": 0.25,
        },
        global_tolerance=0.50,
        residue_externalization_surfaces=("semantic", "linkability"),
    )
    clean_target = TargetProfile(
        name="demo-clean-http-shape",
        signature=kernel.signature_for(objects[1]),
        dimension_tolerances={
            "shape": 0.30,
            "ordering": 0.40,
            "entropy": 0.80,
            "timing": 0.80,
            "semantic": 0.30,
            "linkability": 0.25,
        },
        global_tolerance=0.50,
        residue_externalization_surfaces=("semantic", "linkability"),
    )

    operator_targets = [
        (NormalizeTraceShapeOperator(), analysis_target),
        (BucketTimingOperator(bucket_ms=100), analysis_target),
        (RedactIdentifierFieldsOperator(), clean_target),
    ]

    with tempfile.TemporaryDirectory() as tmp:
        ledger = AuditLedger(Path(tmp) / "chameleon_audit.jsonl")
        for operator, target in operator_targets:
            event = kernel.evaluate(
                obj=objects[0],
                operator=operator,
                target=target,
                authorization=authorization,
                mode="offline_analysis",
            )
            ledger.append(event)
            print(
                f"{operator.name:28s} {event.gate_vector.decision:5s} "
                f"distance={event.gate_vector.global_distance:.3f} "
                f"target={target.name} "
                f"reasons={','.join(event.gate_vector.reasons)}"
            )

        print(f"ledger_entries={len(ledger.read_all())}")
        print(f"ledger_export={ledger.write_jsonl()}")


if __name__ == "__main__":
    main()
