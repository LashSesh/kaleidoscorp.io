from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from chameleon_signature_kernel import ChameleonKernel, SurfaceObject, extract_fingerprint_bundle


def main() -> None:
    obj = SurfaceObject(
        media_type="application/network-observation+http",
        fields={
            "protocol": "http",
            "method": "GET",
            "url": "https://example.test/api/items?limit=1",
            "status": 200,
            "request_headers": {"Accept": "application/json"},
            "request_header_order": ("Accept",),
            "headers": {
                "Content-Type": "application/json",
                "Cache-Control": "no-store",
            },
            "response_header_order": ("Content-Type", "Cache-Control"),
            "duration_ms": 42,
            "body": {"ok": True, "items": [{"id": 1}]},
            "body_length": 31,
        },
        timing_model={"duration_ms": 42},
        declared_protocol_class="http",
    )

    bundle = extract_fingerprint_bundle(obj)
    signature = ChameleonKernel().signature_for(obj)

    print(f"fingerprint_bundle={bundle.digest[:16]}")
    print(f"layers={list(bundle.as_dimensions())}")
    print(f"signature_dimensions={list(signature.dimensions)}")


if __name__ == "__main__":
    main()
