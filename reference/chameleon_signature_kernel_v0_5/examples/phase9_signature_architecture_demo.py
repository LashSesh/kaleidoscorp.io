from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from chameleon_signature_kernel import ChameleonKernel, SurfaceObject, compare_fingerprint_bundles, extract_fingerprint_bundle


def _surface(status: int, content_type: str, path: str, body) -> SurfaceObject:
    fields = {
        "protocol": "http",
        "method": "GET",
        "url": f"https://example.test{path}",
        "status": status,
        "headers": {"Content-Type": content_type, "Cache-Control": "no-store"},
        "response_header_order": ("Content-Type", "Cache-Control"),
        "duration_ms": 42,
        "body": body,
        "body_length": len(str(body)),
    }
    return SurfaceObject(
        media_type="application/network-observation+http",
        fields=fields,
        ordering=tuple(fields),
        timing_model={"duration_ms": 42},
        declared_protocol_class="http",
    )


def main() -> None:
    left = _surface(200, "application/json", "/api/items", {"ok": True, "items": [{"id": 1}]})
    right = _surface(404, "text/plain", "/missing", "not found")

    left_bundle = extract_fingerprint_bundle(left)
    right_bundle = extract_fingerprint_bundle(right)
    bundle_comparison = compare_fingerprint_bundles(left_bundle, right_bundle)

    kernel = ChameleonKernel()
    signature_report = kernel.signature_for(left).compare(kernel.signature_for(right), global_tolerance=0.10)

    print(f"coverage={left_bundle.coverage().layer_count} layers")
    print(f"changed_layers={list(bundle_comparison.changed_layers)}")
    print(f"signature_decision={signature_report.decision}")
    print(f"top_dimensions={list(signature_report.top_dimensions)}")


if __name__ == "__main__":
    main()
