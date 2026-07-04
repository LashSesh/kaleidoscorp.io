from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha256
from typing import Any
from urllib.parse import parse_qsl, urlparse

from .objects import SurfaceObject


FingerprintValue = float | str


@dataclass(frozen=True)
class FingerprintLayerSpec:
    name: str
    category: str
    features: tuple[str, ...]
    description: str


FINGERPRINT_LAYER_SPECS: dict[str, FingerprintLayerSpec] = {
    "http_surface": FingerprintLayerSpec(
        name="http_surface",
        category="protocol",
        features=(
            "method",
            "status_class",
            "content_type_family",
            "request_header_count",
            "response_header_count",
            "path_depth",
            "query_key_count",
        ),
        description="HTTP method/status/header-count/path/query surface.",
    ),
    "http_header_order": FingerprintLayerSpec(
        name="http_header_order",
        category="wire_shape",
        features=(
            "request_order_digest",
            "response_order_digest",
            "first_response_header",
            "last_response_header",
            "response_order_len",
        ),
        description="Header ordering surface without exporting raw header values.",
    ),
    "body_schema": FingerprintLayerSpec(
        name="body_schema",
        category="payload",
        features=("schema_kind", "schema_digest", "schema_depth", "body_length_bucket", "body_truncated"),
        description="Payload schema and size bucket surface.",
    ),
    "transport_timing": FingerprintLayerSpec(
        name="transport_timing",
        category="transport",
        features=("scheme", "host_ref", "host_label_count", "port_class", "duration_bucket"),
        description="Transport-facing timing and endpoint-class surface.",
    ),
    "linkability_surface": FingerprintLayerSpec(
        name="linkability_surface",
        category="privacy",
        features=(
            "request_sensitive_header_count",
            "response_sensitive_header_count",
            "request_sensitive_digest",
            "response_sensitive_digest",
            "has_cookie_surface",
        ),
        description="Sensitive-header and cookie-linkability surface.",
    ),
}

FINGERPRINT_LAYER_NAMES = tuple(FINGERPRINT_LAYER_SPECS)


def _stable_digest(payload: Any) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return sha256(encoded.encode("utf-8")).hexdigest()


def _bucket(raw_value: Any, width: int, max_bucket: int) -> int:
    try:
        raw = float(raw_value)
        return min(max_bucket, max(0, int(raw // width))) if raw >= 0 else -1
    except Exception:
        return -1


def _headers(fields: dict[str, Any], name: str = "headers") -> dict[str, Any]:
    headers = fields.get(name, {})
    return headers if isinstance(headers, dict) else {}


def _header_order(fields: dict[str, Any], order_key: str, headers: dict[str, Any]) -> tuple[str, ...]:
    raw_order = fields.get(order_key, ())
    if isinstance(raw_order, (list, tuple)):
        return tuple(str(item).lower() for item in raw_order)
    return tuple(str(key).lower() for key in headers.keys())


def _content_type_family(headers: dict[str, Any]) -> str:
    content_type = str(headers.get("content-type", headers.get("Content-Type", ""))).lower()
    if not content_type:
        return "unknown"
    return content_type.split(";", 1)[0].strip() or "unknown"


def _body_schema(value: Any, *, depth: int = 0) -> dict[str, Any]:
    if depth > 6:
        return {"kind": "max_depth"}
    if isinstance(value, str):
        try:
            decoded = json.loads(value)
        except Exception:
            return {"kind": "text", "length_bucket": _bucket(len(value), 512, 20)}
        return _body_schema(decoded, depth=depth + 1)
    if isinstance(value, bytes):
        return {"kind": "bytes", "length_bucket": _bucket(len(value), 512, 20)}
    if isinstance(value, dict):
        return {
            "kind": "object",
            "keys": sorted(str(key).lower() for key in value.keys()),
            "children": {
                str(key).lower(): _body_schema(value[key], depth=depth + 1)
                for key in sorted(value.keys(), key=lambda item: str(item).lower())[:24]
            },
        }
    if isinstance(value, list):
        samples = value[:8]
        return {
            "kind": "array",
            "length_bucket": _bucket(len(value), 10, 20),
            "items": [_body_schema(item, depth=depth + 1) for item in samples],
        }
    if value is None:
        return {"kind": "null"}
    if isinstance(value, bool):
        return {"kind": "bool"}
    if isinstance(value, (int, float)):
        return {"kind": "number"}
    return {"kind": type(value).__name__}


def _schema_depth(schema: dict[str, Any]) -> int:
    children = schema.get("children")
    if isinstance(children, dict) and children:
        return 1 + max(_schema_depth(child) for child in children.values() if isinstance(child, dict))
    items = schema.get("items")
    if isinstance(items, list) and items:
        return 1 + max(_schema_depth(item) for item in items if isinstance(item, dict))
    return 1


@dataclass(frozen=True)
class ProtocolFingerprint:
    layer: str
    values: dict[str, FingerprintValue]

    @property
    def digest(self) -> str:
        return _stable_digest({"layer": self.layer, "values": self.values})


@dataclass(frozen=True)
class FingerprintCoverage:
    layer_count: int
    layers: tuple[str, ...]
    missing_layers: tuple[str, ...]
    bundle_digest: str


@dataclass(frozen=True)
class FingerprintBundleComparison:
    left_digest: str
    right_digest: str
    changed_layers: tuple[str, ...]
    unchanged_layers: tuple[str, ...]
    missing_left: tuple[str, ...]
    missing_right: tuple[str, ...]


@dataclass(frozen=True)
class FingerprintBundle:
    fingerprints: tuple[ProtocolFingerprint, ...]

    @property
    def digest(self) -> str:
        return _stable_digest([{"layer": fp.layer, "digest": fp.digest} for fp in self.fingerprints])

    def as_dimensions(self) -> dict[str, dict[str, FingerprintValue]]:
        return {fingerprint.layer: fingerprint.values for fingerprint in self.fingerprints}

    def layer(self, name: str) -> ProtocolFingerprint | None:
        for fingerprint in self.fingerprints:
            if fingerprint.layer == name:
                return fingerprint
        return None

    def layer_digests(self) -> dict[str, str]:
        return {fingerprint.layer: fingerprint.digest for fingerprint in self.fingerprints}

    def coverage(self, expected_layers: tuple[str, ...] = FINGERPRINT_LAYER_NAMES) -> FingerprintCoverage:
        layers = tuple(sorted(fingerprint.layer for fingerprint in self.fingerprints))
        missing = tuple(layer for layer in expected_layers if layer not in layers)
        return FingerprintCoverage(
            layer_count=len(layers),
            layers=layers,
            missing_layers=missing,
            bundle_digest=self.digest,
        )

    def explain(self) -> dict[str, dict[str, str | tuple[str, ...]]]:
        return {
            fingerprint.layer: {
                "category": FINGERPRINT_LAYER_SPECS.get(
                    fingerprint.layer,
                    FingerprintLayerSpec(fingerprint.layer, "unknown", (), "unknown layer"),
                ).category,
                "digest": fingerprint.digest,
                "features": tuple(fingerprint.values.keys()),
            }
            for fingerprint in self.fingerprints
        }


def fingerprint_layer_specs() -> tuple[FingerprintLayerSpec, ...]:
    return tuple(FINGERPRINT_LAYER_SPECS[name] for name in FINGERPRINT_LAYER_NAMES)


def compare_fingerprint_bundles(left: FingerprintBundle, right: FingerprintBundle) -> FingerprintBundleComparison:
    left_layers = left.layer_digests()
    right_layers = right.layer_digests()
    shared = sorted(set(left_layers).intersection(right_layers))
    changed = tuple(layer for layer in shared if left_layers[layer] != right_layers[layer])
    unchanged = tuple(layer for layer in shared if left_layers[layer] == right_layers[layer])
    return FingerprintBundleComparison(
        left_digest=left.digest,
        right_digest=right.digest,
        changed_layers=changed,
        unchanged_layers=unchanged,
        missing_left=tuple(sorted(set(right_layers).difference(left_layers))),
        missing_right=tuple(sorted(set(left_layers).difference(right_layers))),
    )


def extract_fingerprint_bundle(obj: SurfaceObject) -> FingerprintBundle:
    fields = dict(obj.fields)
    response_headers = _headers(fields)
    request_headers = _headers(fields, "request_headers")
    response_order = _header_order(fields, "response_header_order", response_headers)
    request_order = _header_order(fields, "request_header_order", request_headers)

    parsed_url = urlparse(str(fields.get("url", "")))
    query_keys = tuple(sorted(key.lower() for key, _ in parse_qsl(parsed_url.query, keep_blank_values=True)))
    status = fields.get("status", fields.get("status_code", -1))
    try:
        status_class = int(status) // 100
    except Exception:
        status_class = -1

    body_value = fields.get("body")
    body_schema = _body_schema(body_value) if body_value not in (None, "", {}, []) else {"kind": "absent"}
    body_length = fields.get("body_length", len(str(body_value)) if body_value not in (None, "", {}, []) else 0)
    duration = fields.get("duration_ms", obj.timing_model.get("duration_ms", -1))

    sensitive_header_names = {
        "authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-forwarded-for",
        "forwarded",
    }
    response_sensitive = sorted(set(response_order).intersection(sensitive_header_names))
    request_sensitive = sorted(set(request_order).intersection(sensitive_header_names))

    fingerprints = (
        ProtocolFingerprint(
            layer="http_surface",
            values={
                "method": str(fields.get("method", "unknown")).upper(),
                "status_class": float(status_class),
                "content_type_family": _content_type_family(response_headers),
                "request_header_count": float(len(request_headers)),
                "response_header_count": float(len(response_headers)),
                "path_depth": float(len([part for part in parsed_url.path.split("/") if part])),
                "query_key_count": float(len(query_keys)),
            },
        ),
        ProtocolFingerprint(
            layer="http_header_order",
            values={
                "request_order_digest": _stable_digest(request_order),
                "response_order_digest": _stable_digest(response_order),
                "first_response_header": response_order[0] if response_order else "",
                "last_response_header": response_order[-1] if response_order else "",
                "response_order_len": float(len(response_order)),
            },
        ),
        ProtocolFingerprint(
            layer="body_schema",
            values={
                "schema_kind": str(body_schema.get("kind", "unknown")),
                "schema_digest": _stable_digest(body_schema),
                "schema_depth": float(_schema_depth(body_schema)),
                "body_length_bucket": float(_bucket(body_length, 512, 50)),
                "body_truncated": 1.0 if fields.get("body_truncated") else 0.0,
            },
        ),
        ProtocolFingerprint(
            layer="transport_timing",
            values={
                "scheme": parsed_url.scheme or "unknown",
                "host_ref": _stable_digest((parsed_url.hostname or "").lower())[:16],
                "host_label_count": float(len([part for part in (parsed_url.hostname or "").split(".") if part])),
                "port_class": str(parsed_url.port or ("default_https" if parsed_url.scheme == "https" else "default_http")),
                "duration_bucket": float(_bucket(duration, 100, 50)),
            },
        ),
        ProtocolFingerprint(
            layer="linkability_surface",
            values={
                "request_sensitive_header_count": float(len(request_sensitive)),
                "response_sensitive_header_count": float(len(response_sensitive)),
                "request_sensitive_digest": _stable_digest(request_sensitive),
                "response_sensitive_digest": _stable_digest(response_sensitive),
                "has_cookie_surface": 1.0 if {"cookie", "set-cookie"}.intersection(request_sensitive + response_sensitive) else 0.0,
            },
        ),
    )
    return FingerprintBundle(fingerprints=fingerprints)
