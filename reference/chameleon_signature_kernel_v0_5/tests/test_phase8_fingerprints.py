from chameleon_signature_kernel import (
    ChameleonKernel,
    NetworkAdapter,
    NetworkAdapterConfig,
    NetworkRequest,
    NetworkResponse,
    calibration_preset_names,
    extract_fingerprint_bundle,
)
from chameleon_signature_kernel.objects import SurfaceObject
from chameleon_signature_kernel.policy import AuthorizationManifest


class FakeTransport:
    def send(self, request, config):
        return NetworkResponse(
            url=request.url,
            method=request.method,
            status=200,
            headers={
                "Content-Type": "application/json",
                "Cache-Control": "no-store",
                "Set-Cookie": "secret",
            },
            body=b'{"ok": true, "items": [{"id": 1}]}',
            duration_ms=37,
        )


def test_extract_fingerprint_bundle_layers_from_network_object():
    auth = AuthorizationManifest("owned", "tester", "approved", ("network_observation",))
    adapter = NetworkAdapter(
        auth,
        config=NetworkAdapterConfig(allowed_hosts=("example.test",), include_body=True),
        transport=FakeTransport(),
    )
    obj = adapter.fetch(NetworkRequest("https://example.test/api/items?limit=1"))
    bundle = extract_fingerprint_bundle(obj)
    layers = bundle.as_dimensions()

    assert {"http_surface", "http_header_order", "body_schema", "transport_timing", "linkability_surface"} <= set(layers)
    assert layers["http_surface"]["content_type_family"] == "application/json"
    assert layers["body_schema"]["schema_kind"] == "object"
    assert layers["linkability_surface"]["has_cookie_surface"] == 1.0
    assert bundle.digest


def test_kernel_signature_contains_fingerprint_dimensions():
    obj = SurfaceObject(
        media_type="application/network-observation+http",
        fields={
            "protocol": "http",
            "method": "GET",
            "url": "https://example.test/status",
            "status": 204,
            "headers": {"Content-Type": "text/plain"},
            "response_header_order": ("Content-Type",),
            "duration_ms": 20,
            "body_length": 0,
        },
        timing_model={"duration_ms": 20},
        declared_protocol_class="http",
    )
    signature = ChameleonKernel().signature_for(obj)
    assert "http_surface" in signature.dimensions
    assert "http_header_order" in signature.dimensions
    assert signature.dimensions["http_surface"]["status_class"] == 2.0


def test_http_fingerprint_preset_is_available():
    assert "HTTP fingerprint" in calibration_preset_names()
