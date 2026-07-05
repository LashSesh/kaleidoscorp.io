import json

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


def _fixture():
    auth = AuthorizationManifest(
        source_name="test-local",
        owner_or_controller="tester",
        permission_basis="synthetic unit test fixture",
    )
    objects = TraceAdapter(authorization=auth).from_records(
        [
            {
                "id": "r1",
                "method": "GET",
                "url": "https://example.local/a",
                "status": 200,
                "headers": {"User-Agent": "TestClient/1.0"},
                "duration_ms": 100,
                "delta_ms": 20,
            },
            {
                "id": "r2",
                "method": "GET",
                "url": "https://example.local/b",
                "status": 200,
                "headers": {"User-Agent": "TestClient/1.0"},
                "duration_ms": 110,
                "delta_ms": 25,
            },
        ],
    )
    kernel = ChameleonKernel()
    corpus = ProfileCorpus()
    profile = corpus.build_profile(
        name="test_profile",
        version="1.0.0",
        signatures=[kernel.signature_for(obj) for obj in objects],
    )
    target = profile.to_target_profile(global_tolerance=0.75)
    return auth, objects, kernel, target


def test_controlled_adapter_builds_plan_without_raw_trace_export():
    auth, objects, kernel, target = _fixture()
    framework = ControlledAdapterFramework(kernel=kernel)
    intent = ControlIntent(
        objective="authorized adapter operation for signature normalization",
        target_profile_name=target.name,
        export_level="operational_plan",
    )

    plan = framework.build_plan(
        intent=intent,
        objects=objects,
        operators=(NormalizeTraceShapeOperator(), BucketTimingOperator()),
        target=target,
        authorization=auth,
    )
    bundle = framework.export_bundle(plan)
    payload = bundle.to_dict()

    assert plan.adapter_policy_decision.decision == "PASS"
    assert len(plan.steps) == 4
    assert plan.overall_decision in {"PASS", "OPTIMIZE"}
    assert payload["execution_contract"]["execution"] == "supported_for_configured_adapters"
    encoded = json.dumps(payload)
    assert "https://example.local/a" not in encoded
    assert "https://example.local/b" not in encoded
    assert "object_ref" in encoded
    assert "residue_ref" in encoded


def test_controlled_adapter_allows_authorized_network_observation():
    auth, objects, kernel, target = _fixture()
    framework = ControlledAdapterFramework(kernel=kernel)
    intent = ControlIntent(
        objective="authorized network observation",
        target_profile_name=target.name,
        requested_network_io=True,
        mode="network_observation",
    )

    plan = framework.build_plan(
        intent=intent,
        objects=objects,
        operators=(NormalizeTraceShapeOperator(),),
        target=target,
        authorization=auth,
    )

    assert plan.adapter_policy_decision.decision == "PASS"
    assert len(plan.steps) == 2
    assert plan.overall_decision in {"PASS", "OPTIMIZE"}


def test_controlled_adapter_rejects_unsupported_capabilities():
    auth, objects, kernel, target = _fixture()
    framework = ControlledAdapterFramework(kernel=kernel)
    intent = ControlIntent(
        objective="authorized adapter operation",
        target_profile_name=target.name,
        capabilities=("network_observation", "live_packet_manipulation"),
    )

    plan = framework.build_plan(
        intent=intent,
        objects=objects,
        operators=(NormalizeTraceShapeOperator(),),
        target=target,
        authorization=auth,
    )

    assert plan.overall_decision == "FAIL"
    assert plan.adapter_policy_decision.reason.startswith("unsupported_capability:")
    assert plan.steps == ()


def test_export_bundle_can_write_json(tmp_path):
    auth, objects, kernel, target = _fixture()
    framework = ControlledAdapterFramework(kernel=kernel)
    intent = ControlIntent(
        objective="adapter feedback export",
        target_profile_name=target.name,
        mode="audit_export",
        export_level="effectiveness_feedback",
    )
    plan = framework.build_plan(
        intent=intent,
        objects=objects[:1],
        operators=(NormalizeTraceShapeOperator(),),
        target=target,
        authorization=auth,
    )
    path = framework.export_bundle(plan).write_json(tmp_path / "plan.json")
    loaded = json.loads(path.read_text())
    assert loaded["plan"]["plan_id"] == plan.plan_id
    assert loaded["execution_contract"]["raw_trace_export"] == "not_included"
