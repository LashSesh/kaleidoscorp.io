from __future__ import annotations

from dataclasses import dataclass
from math import log2
from typing import Any

from .canonicalizer import CanonicalObject
from .fingerprints import extract_fingerprint_bundle
from .objects import SurfaceObject


SENSITIVE_FIELD_HINTS = {
    "authorization", "cookie", "set-cookie", "x-api-key", "api_key",
    "token", "session", "session_id", "client_ip", "remote_addr",
    "forwarded", "x-forwarded-for", "x_forwarded_for", "user_id", "device_id",
}


@dataclass(frozen=True)
class FeatureVector:
    shape_features: dict[str, float | str]
    ordering_features: dict[str, float | str]
    entropy_features: dict[str, float | str]
    timing_features: dict[str, float | str]
    semantic_features: dict[str, float | str]
    linkability_features: dict[str, float | str]
    fingerprint_features: dict[str, dict[str, float | str]]

    def as_dimensions(self) -> dict[str, dict[str, float | str]]:
        dimensions = {
            "shape": self.shape_features,
            "ordering": self.ordering_features,
            "entropy": self.entropy_features,
            "timing": self.timing_features,
            "semantic": self.semantic_features,
            "linkability": self.linkability_features,
        }
        dimensions.update(self.fingerprint_features)
        return dimensions


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    total = len(text)
    return -sum((count / total) * log2(count / total) for count in counts.values())


def _count_nested_fields(value: Any) -> int:
    if isinstance(value, dict):
        return len(value) + sum(_count_nested_fields(v) for v in value.values())
    if isinstance(value, list):
        return sum(_count_nested_fields(v) for v in value)
    return 0


def _headers(fields: dict[str, Any]) -> dict[str, Any]:
    headers = fields.get("headers", {})
    return headers if isinstance(headers, dict) else {}


def _sensitive_hits(fields: dict[str, Any]) -> set[str]:
    hits: set[str] = set()

    def walk(value: Any, key: str = "") -> None:
        key_l = key.lower()
        if key_l in SENSITIVE_FIELD_HINTS or any(hint in key_l for hint in SENSITIVE_FIELD_HINTS):
            hits.add(key_l)
        if isinstance(value, dict):
            for nested_key, nested_value in value.items():
                walk(nested_value, str(nested_key))
        elif isinstance(value, list):
            for item in value:
                walk(item, key)

    walk(fields)
    return {h for h in hits if h}


def extract_features(canonical: CanonicalObject, original: SurfaceObject | None = None) -> FeatureVector:
    fields = dict(canonical.canonical_fields)
    headers = _headers(fields)
    serialized = repr(fields)
    sensitive = _sensitive_hits(fields)
    timing = dict(original.timing_model) if original else {}
    fingerprint_features = extract_fingerprint_bundle(original).as_dimensions() if original else {}

    status = fields.get("status", fields.get("status_code", "unknown"))
    try:
        status_class = int(status) // 100
    except Exception:
        status_class = -1

    def bucket(raw_value: Any, width: int, max_bucket: int) -> int:
        try:
            raw = float(raw_value)
            return min(max_bucket, max(0, int(raw // width))) if raw >= 0 else -1
        except Exception:
            return -1

    interarrival_ms = timing.get("interarrival_ms", timing.get("delta_ms", -1))
    jitter_ms = timing.get("jitter_ms", -1)

    return FeatureVector(
        shape_features={
            "field_count": float(len(fields)),
            "nested_field_count": float(sum(_count_nested_fields(v) for v in fields.values())),
            "header_count": float(len(headers)),
            "has_body": 1.0 if fields.get("body") not in (None, "", {}, []) else 0.0,
            "media_type": canonical.media_type,
        },
        ordering_features={
            "declared_order_len": float(len(original.ordering) if original else len(fields)),
            "canonical_order_len": float(len(fields)),
            "first_key": str(next(iter(fields.keys()), "")),
        },
        entropy_features={
            "payload_length": float(len(serialized)),
            "shannon_entropy": round(_shannon_entropy(serialized), 6),
        },
        timing_features={
            "interarrival_bucket": float(bucket(interarrival_ms, 100, 10)),
            "jitter_bucket": float(bucket(jitter_ms, 50, 10)),
            "has_timing": 1.0 if timing else 0.0,
        },
        semantic_features={
            "declared_protocol_class": canonical.declared_protocol_class,
            "method": str(fields.get("method", "unknown")).upper(),
            "status_class": float(status_class),
        },
        linkability_features={
            "sensitive_field_count": float(len(sensitive)),
            "has_authorization": 1.0 if "authorization" in sensitive else 0.0,
            "has_cookie": 1.0 if "cookie" in sensitive or "set-cookie" in sensitive else 0.0,
            "has_ip_surface": 1.0 if sensitive.intersection({"client_ip", "remote_addr", "x-forwarded-for", "x_forwarded_for", "forwarded"}) else 0.0,
        },
        fingerprint_features=fingerprint_features,
    )
