from chameleon_signature_kernel import AuthorizationManifest
from chameleon_signature_kernel.adapters import TraceAdapter, TraceImportError


def _auth():
    return AuthorizationManifest("owned-jsonl", "me", "self-owned", ("offline_analysis",))


def test_trace_adapter_requires_valid_authorization():
    bad = AuthorizationManifest("", "", "", ())
    try:
        TraceAdapter(bad)
    except TraceImportError as exc:
        assert "authorization" in str(exc)
    else:
        raise AssertionError("expected TraceImportError")


def test_jsonl_importer(tmp_path):
    p = tmp_path / "trace.jsonl"
    p.write_text('{"protocol":"http","method":"GET","interarrival_ms":50}\n', encoding="utf-8")
    objects = TraceAdapter(_auth()).from_jsonl_file(p)
    assert len(objects) == 1
    assert objects[0].declared_protocol_class == "http"
    assert objects[0].timing_model["interarrival_ms"] == 50


def test_har_like_importer():
    har = {
        "log": {
            "entries": [
                {
                    "request": {
                        "method": "GET",
                        "url": "https://example.test",
                        "headers": [{"name": "User-Agent", "value": "Demo"}],
                    },
                    "response": {"status": 200},
                    "time": 42,
                }
            ]
        }
    }
    objects = TraceAdapter(_auth()).from_har_dict(har)
    assert objects[0].fields["method"] == "GET"
    assert objects[0].fields["status"] == 200
    assert objects[0].timing_model["duration_ms"] == 42
