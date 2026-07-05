import json

from chameleon_signature_kernel import ChameleonGuiModel, NetworkResponse, calibration_spectrum, get_calibration_preset


class FakeTransport:
    def send(self, request, config):
        return NetworkResponse(
            url=request.url,
            method=request.method,
            status=200,
            headers={"Content-Type": "text/plain"},
            body=b"ok",
            duration_ms=9,
        )


class RecordingTransport:
    def __init__(self):
        self.urls = []

    def send(self, request, config):
        self.urls.append(request.url)
        return NetworkResponse(
            url=request.url,
            method=request.method,
            status=200,
            headers={"Content-Type": "application/json"},
            body=b'{"ok":true}',
            duration_ms=11,
        )


def test_calibration_spectrum_exposes_operational_presets():
    presets = calibration_spectrum()
    names = {preset.name for preset in presets}
    dimensions = {dimension for preset in presets for dimension in preset.dimensions}
    assert {"Domain surface", "HTTP fingerprint", "Endpoint shape", "API family", "Timing stability", "Header/body surface"} <= names
    assert {
        "shape",
        "ordering",
        "entropy",
        "timing",
        "semantic",
        "linkability",
        "http_surface",
        "http_header_order",
        "body_schema",
        "transport_timing",
        "linkability_surface",
    } <= dimensions


def test_gui_model_runs_closed_trace_workflow(tmp_path):
    model = ChameleonGuiModel()
    auth = model.build_authorization(
        source_name="gui-fixture",
        owner_or_controller="tester",
        permission_basis="owned fixture",
    )
    model.import_records(
        [
            {
                "protocol": "http",
                "method": "GET",
                "url": "https://example.local/a",
                "status": 200,
                "duration_ms": 25,
            }
        ],
        auth,
    )
    model.build_mask(name="gui_mask", version="1.0.0")
    iteration = model.run_iteration(
        authorization=auth,
        operator_names=("Normalize shape",),
        max_rounds=2,
    )
    model.build_plan(
        authorization=auth,
        objective="authorized adapter operation",
        operator_names=("Normalize shape", "Sort fields"),
    )
    plan_path = model.export_plan(tmp_path / "plan.json")
    ledger_path = model.export_ledger(tmp_path / "audit.jsonl")

    payload = json.loads(plan_path.read_text(encoding="utf-8"))
    assert payload["execution_contract"]["execution"] == "supported_for_configured_adapters"
    assert payload["plan"]["overall_decision"] in {"PASS", "OPTIMIZE"}
    assert iteration.stop_reason in {"already_converged", "converged", "no_candidate_improved", "no_significant_improvement"}
    assert ledger_path.read_text(encoding="utf-8").strip()


def test_gui_model_fetches_network_observation_with_injected_transport():
    model = ChameleonGuiModel()
    auth = model.build_authorization(
        source_name="owned-service",
        owner_or_controller="tester",
        permission_basis="approved observation",
        allow_network=True,
    )
    obj = model.fetch_network_observation(
        url="https://example.test/status",
        authorization=auth,
        transport=FakeTransport(),
    )
    snapshot = model.snapshot()
    assert obj.fields["status"] == 200
    assert snapshot.object_count == 1


def test_gui_model_calibrates_domain_target_with_selected_preset():
    model = ChameleonGuiModel()
    auth = model.build_authorization(
        source_name="owned-service",
        owner_or_controller="tester",
        permission_basis="approved observation",
        allow_network=True,
    )
    transport = RecordingTransport()
    result = model.calibrate_target(
        base_url="https://example.test",
        paths=("/", "/health", "api/items"),
        authorization=auth,
        mask_name="example_api",
        calibration_preset="Endpoint shape",
        transport=transport,
    )
    preset = get_calibration_preset("Endpoint shape")
    assert result.object_count == 3
    assert result.mask_name == "example_api@1.0.0"
    assert tuple(transport.urls) == result.urls
    assert model.mask is not None
    assert model.mask.dimension_tolerances == preset.dimension_tolerances


def test_gui_model_rejects_cross_host_calibration_path():
    model = ChameleonGuiModel()
    auth = model.build_authorization(
        source_name="owned-service",
        owner_or_controller="tester",
        permission_basis="approved observation",
        allow_network=True,
    )
    try:
        model.calibrate_target(
            base_url="https://example.test",
            paths=("https://other.test/status",),
            authorization=auth,
            mask_name="bad",
            transport=FakeTransport(),
        )
    except ValueError as exc:
        assert "base host" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_gui_model_calibration_paths_can_be_relative_to_base_path():
    model = ChameleonGuiModel()
    urls = model._calibration_urls(base_url="https://example.test/api", paths=("users", "orders"))
    assert urls == ("https://example.test/api/users", "https://example.test/api/orders")


def test_gui_model_can_rebuild_mask_without_duplicate_profile_error():
    model = ChameleonGuiModel()
    auth = model.build_authorization(
        source_name="gui-fixture",
        owner_or_controller="tester",
        permission_basis="owned fixture",
    )
    model.import_records([{"protocol": "http", "method": "GET", "status": 200}], auth)
    first = model.build_mask(name="repeatable", version="1.0.0")
    second = model.build_mask(name="repeatable", version="1.0.0")
    assert first.name == second.name == "repeatable@1.0.0"


def test_gui_action_state_matches_closed_workflow():
    model = ChameleonGuiModel()
    ready = {"auth_ready": True, "url_ready": True, "network_authorized": True, "selected_operator_count": 1}
    state = model.action_state(**ready)
    assert state.import_trace is True
    assert state.fetch_network is True
    assert state.calibrate_target is False
    assert state.build_mask is False
    assert state.build_plan is False
    assert state.run_iteration is False
    assert state.export_plan is False

    state = model.action_state(**{**ready, "calibration_ready": True})
    assert state.calibrate_target is True

    auth = model.build_authorization(
        source_name="gui-fixture",
        owner_or_controller="tester",
        permission_basis="owned fixture",
    )
    model.import_records([{"protocol": "http", "method": "GET", "status": 200}], auth)
    state = model.action_state(**ready)
    assert state.build_mask is True
    assert state.build_plan is False

    model.build_mask(name="actions", version="1.0.0")
    state = model.action_state(**ready)
    assert state.build_plan is True
    assert state.run_iteration is True
    assert state.export_plan is False

    model.build_plan(
        authorization=auth,
        objective="authorized adapter operation",
        operator_names=("Normalize shape",),
    )
    state = model.action_state(**ready)
    assert state.export_plan is True
    assert state.export_ledger is True
