from chameleon_signature_kernel import (
    AuthorizationManifest,
    NetworkAdapter,
    NetworkAdapterConfig,
    NetworkAdapterError,
    NetworkRequest,
    NetworkResponse,
)


class FakeTransport:
    def send(self, request, config):
        return NetworkResponse(
            url=request.url,
            method=request.method,
            status=200,
            headers={"Content-Type": "application/json", "Set-Cookie": "secret"},
            body=b'{"ok":true}',
            duration_ms=12,
        )


def _auth():
    return AuthorizationManifest(
        "owned-endpoint",
        "me",
        "self-owned service",
        ("network_observation",),
    )


def test_network_adapter_converts_response_to_surface_object():
    adapter = NetworkAdapter(
        _auth(),
        config=NetworkAdapterConfig(allowed_hosts=("example.test",)),
        transport=FakeTransport(),
    )
    obj = adapter.fetch(NetworkRequest("https://example.test/status"))
    assert obj.declared_protocol_class == "http"
    assert obj.fields["status"] == 200
    assert obj.fields["body_length"] == len(b'{"ok":true}')
    assert obj.fields["body_truncated"] is False
    assert obj.fields["headers"]["Set-Cookie"] == "<redacted>"
    assert obj.timing_model["duration_ms"] == 12


def test_network_adapter_rejects_unconfigured_methods():
    adapter = NetworkAdapter(_auth(), transport=FakeTransport())
    try:
        adapter.fetch(NetworkRequest("https://example.test/status", method="POST"))
    except NetworkAdapterError as exc:
        assert "method_not_allowed" in str(exc)
    else:
        raise AssertionError("expected NetworkAdapterError")
