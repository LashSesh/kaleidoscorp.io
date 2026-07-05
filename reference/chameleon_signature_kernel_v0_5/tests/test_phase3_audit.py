from chameleon_signature_kernel import AuthorizationManifest, ChameleonKernel, NormalizeTraceShapeOperator, TargetProfile
from chameleon_signature_kernel.audit_ledger import AuditLedger
from chameleon_signature_kernel.objects import SurfaceObject


def test_audit_ledger_is_memory_only_until_explicit_export(tmp_path):
    obj = SurfaceObject(
        media_type="application/trace+json",
        fields={"protocol": "http", "method": "GET", "status": 200},
        declared_protocol_class="http",
    )
    auth = AuthorizationManifest("owned", "me", "self-owned", ("offline_analysis",))
    kernel = ChameleonKernel()
    target = TargetProfile(name="self", signature=kernel.signature_for(obj))
    event = kernel.evaluate(obj=obj, operator=NormalizeTraceShapeOperator(), target=target, authorization=auth)

    path = tmp_path / "audit.jsonl"
    ledger = AuditLedger(path)
    ledger.append(event)
    ledger.append(event)

    entries = ledger.read_all()
    assert len(entries) == 2
    assert entries[0]["operator_name"] == "normalize_trace_shape"
    assert not path.exists()
    ledger.write_jsonl()
    assert path.exists()
