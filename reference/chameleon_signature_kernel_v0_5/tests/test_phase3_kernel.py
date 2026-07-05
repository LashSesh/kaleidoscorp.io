from chameleon_signature_kernel import (
    AuthorizationManifest,
    BucketTimingOperator,
    ChameleonKernel,
    NormalizeTraceShapeOperator,
    RedactIdentifierFieldsOperator,
    TargetProfile,
)
from chameleon_signature_kernel.objects import SurfaceObject


def _auth():
    return AuthorizationManifest("owned-trace", "me", "self-owned", ("offline_analysis", "offline_redaction"))


def _obj(with_sensitive=True):
    fields = {
        "protocol": "http",
        "method": "GET",
        "url": "https://example.test/api",
        "headers": {"User-Agent": "Demo/1.0"},
        "status": 200,
        "interarrival_ms": 123,
        "jitter_ms": 17,
    }
    if with_sensitive:
        fields["headers"]["Authorization"] = "Bearer local-demo"
        fields["client_ip"] = "192.0.2.10"
    return SurfaceObject(
        media_type="application/trace+json",
        fields=fields,
        ordering=tuple(fields),
        timing_model={"interarrival_ms": 123, "jitter_ms": 17},
        declared_protocol_class="http",
        provenance={"source": "test"},
    )


def _target_for(obj):
    kernel = ChameleonKernel()
    return TargetProfile(
        name="target",
        signature=kernel.signature_for(obj),
        dimension_tolerances={
            "shape": 0.5,
            "ordering": 0.5,
            "entropy": 1.0,
            "timing": 1.0,
            "semantic": 0.5,
            "linkability": 0.5,
        },
        global_tolerance=0.8,
        residue_externalization_surfaces=("semantic", "linkability"),
    )


def test_signature_detects_linkability_surface():
    kernel = ChameleonKernel()
    sig = kernel.signature_for(_obj(with_sensitive=True))
    assert sig.dimensions["linkability"]["sensitive_field_count"] >= 2
    assert sig.dimensions["linkability"]["has_authorization"] == 1.0
    assert sig.dimensions["linkability"]["has_ip_surface"] == 1.0


def test_normalize_trace_shape_can_pass_or_hold_against_self_target():
    obj = _obj(with_sensitive=False)
    kernel = ChameleonKernel()
    event = kernel.evaluate(
        obj=obj,
        operator=NormalizeTraceShapeOperator(),
        target=_target_for(obj),
        authorization=_auth(),
    )
    assert event.gate_vector.decision in {"PASS", "OPTIMIZE"}
    assert event.policy_decision.decision == "PASS"
    assert event.replay_manifest.digest()
    assert event.replay_feedback.decision in {"PASS", "OPTIMIZE"}


def test_redaction_creates_linkability_and_semantic_residue():
    obj = _obj(with_sensitive=True)
    result = RedactIdentifierFieldsOperator().apply(obj)
    assert result.residue_report.by_surface("linkability")
    assert result.residue_report.by_surface("semantic")


def test_redaction_externalizes_linkability_residue_for_optimization():
    source = _obj(with_sensitive=True)
    clean = _obj(with_sensitive=False)
    kernel = ChameleonKernel()
    event = kernel.evaluate(
        obj=source,
        operator=RedactIdentifierFieldsOperator(),
        target=_target_for(clean),
        authorization=_auth(),
    )
    assert event.gate_vector.decision == "OPTIMIZE"
    assert "residue_externalized" in event.gate_vector.reasons
    assert event.residue_report.externalize() is not None


def test_bucket_timing_is_not_live_action_and_produces_timing_residue():
    obj = _obj(with_sensitive=False)
    kernel = ChameleonKernel()
    event = kernel.evaluate(
        obj=obj,
        operator=BucketTimingOperator(bucket_ms=100),
        target=_target_for(obj),
        authorization=_auth(),
        mode="offline_analysis",
    )
    assert event.policy_decision.decision == "PASS"
    assert event.residue_report.by_surface("timing")


def test_missing_authorization_fails_even_if_signature_close():
    obj = _obj(with_sensitive=False)
    kernel = ChameleonKernel()
    event = kernel.evaluate(
        obj=obj,
        operator=NormalizeTraceShapeOperator(),
        target=_target_for(obj),
        authorization=None,
    )
    assert event.gate_vector.decision == "FAIL"
    assert event.gate_vector.failed_dimensions == ("policy",)


def test_batch_analysis_counts_decisions():
    objs = [_obj(with_sensitive=False), _obj(with_sensitive=False)]
    kernel = ChameleonKernel()
    result = kernel.analyze_batch(
        objects=objs,
        operator=NormalizeTraceShapeOperator(),
        target=_target_for(objs[0]),
        authorization=_auth(),
    )
    assert sum(result.decisions().values()) == 2
