from chameleon_signature_kernel import (
    AuthorizationManifest,
    ChameleonKernel,
    ControlledAdapterFramework,
    ControlIntent,
    NormalizeTraceShapeOperator,
    SurfaceObject,
    TargetProfile,
    compare_fingerprint_bundles,
    extract_fingerprint_bundle,
    fingerprint_layer_specs,
)


def _obj(status=200, content_type="application/json", path="/api/items", body=None):
    fields = {
        "protocol": "http",
        "method": "GET",
        "url": f"https://example.test{path}",
        "status": status,
        "headers": {"Content-Type": content_type, "Cache-Control": "no-store"},
        "response_header_order": ("Content-Type", "Cache-Control"),
        "duration_ms": 42,
        "body_length": 0,
    }
    if body is not None:
        fields["body"] = body
        fields["body_length"] = len(str(body))
    return SurfaceObject(
        media_type="application/network-observation+http",
        fields=fields,
        ordering=tuple(fields),
        timing_model={"duration_ms": 42},
        declared_protocol_class="http",
    )


def test_fingerprint_bundle_coverage_and_comparison_are_first_class():
    first = extract_fingerprint_bundle(_obj(body={"ok": True}))
    second = extract_fingerprint_bundle(_obj(status=404, content_type="text/plain", path="/missing", body="nope"))
    coverage = first.coverage()
    comparison = compare_fingerprint_bundles(first, second)

    assert coverage.layer_count == 5
    assert coverage.missing_layers == ()
    assert "http_surface" in comparison.changed_layers
    assert fingerprint_layer_specs()[0].name == "http_surface"


def test_spectral_signature_comparison_report_explains_top_dimensions():
    kernel = ChameleonKernel()
    left = kernel.signature_for(_obj(body={"ok": True}))
    right = kernel.signature_for(_obj(status=404, content_type="text/plain", path="/missing", body="nope"))
    report = left.compare(right, global_tolerance=0.01)

    assert report.global_distance > 0
    assert report.decision == "OPTIMIZE"
    assert report.top_dimensions
    assert "http_surface" in {delta.dimension for delta in report.dimension_deltas}


def test_control_plan_steps_include_signature_report_fields():
    auth = AuthorizationManifest("owned", "tester", "approved", ("offline_analysis", "adapter_operation"))
    source = _obj(body={"ok": True})
    target_obj = _obj(status=404, content_type="text/plain", path="/missing", body="nope")
    kernel = ChameleonKernel()
    target = TargetProfile(
        name="target",
        signature=kernel.signature_for(target_obj),
        global_tolerance=0.01,
        dimension_tolerances={"http_surface": 0.01},
    )
    plan = ControlledAdapterFramework(kernel=kernel).build_plan(
        intent=ControlIntent(
            objective="authorized adapter operation",
            target_profile_name=target.name,
        ),
        objects=(source,),
        operators=(NormalizeTraceShapeOperator(),),
        target=target,
        authorization=auth,
    )

    assert plan.steps[0].signature_distance > 0
    assert plan.steps[0].signature_decision in {"PASS", "OPTIMIZE"}
    assert plan.steps[0].top_drift_dimensions
