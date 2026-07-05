from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .objects import SurfaceObject
from .residue_report import ResidueReport
from .transform_operator import TransformResult


@dataclass(frozen=True)
class SortFieldsOperator:
    name: str = "sort_fields"
    risk_level: str = "low"
    preserves_semantics: bool = True

    def apply(self, obj: SurfaceObject) -> TransformResult:
        new_fields = {key: obj.fields[key] for key in sorted(obj.fields.keys(), key=str)}
        residue = ResidueReport().add("ordering", "low", "field order normalized")
        return TransformResult(
            transformed=obj.with_fields(new_fields, provenance_note=self.name),
            residue_report=residue,
            explanation="Sorted top-level fields for canonical shape comparison.",
        )


@dataclass(frozen=True)
class NormalizeTraceShapeOperator:
    name: str = "normalize_trace_shape"
    risk_level: str = "low"
    preserves_semantics: bool = True

    def apply(self, obj: SurfaceObject) -> TransformResult:
        fields: dict[str, Any] = {}
        for key, value in obj.fields.items():
            normalized_key = str(key).strip().lower().replace("-", "_")
            fields[normalized_key] = value
        residue = ResidueReport().add("shape", "low", "field names normalized for trace comparison")
        return TransformResult(
            transformed=obj.with_fields(fields, provenance_note=self.name),
            residue_report=residue,
            explanation="Normalized trace field names without changing values.",
        )


@dataclass(frozen=True)
class RedactIdentifierFieldsOperator:
    name: str = "redact_identifier_fields"
    risk_level: str = "medium"
    preserves_semantics: bool = False
    placeholder: str = "<redacted>"

    sensitive_key_fragments: tuple[str, ...] = (
        "authorization", "cookie", "token", "api_key", "session",
        "client_ip", "remote_addr", "x_forwarded_for", "x-forwarded-for",
        "user_id", "device_id",
    )

    def _redact(self, value: Any, key: str = "") -> tuple[Any, int]:
        key_l = key.lower()
        if any(fragment in key_l for fragment in self.sensitive_key_fragments):
            return self.placeholder, 1
        if isinstance(value, dict):
            redacted: dict[str, Any] = {}
            count = 0
            for nested_key, nested_value in value.items():
                new_value, n = self._redact(nested_value, str(nested_key))
                redacted[nested_key] = new_value
                count += n
            return redacted, count
        if isinstance(value, list):
            out = []
            count = 0
            for item in value:
                new_item, n = self._redact(item, key)
                out.append(new_item)
                count += n
            return out, count
        return value, 0

    def apply(self, obj: SurfaceObject) -> TransformResult:
        fields: dict[str, Any] = {}
        count = 0
        for key, value in obj.fields.items():
            new_value, n = self._redact(value, str(key))
            fields[key] = new_value
            count += n
        severity = "medium" if count else "low"
        residue = ResidueReport().add("linkability", severity, f"redacted {count} identifier-bearing fields")
        if count:
            residue = residue.add("semantic", "medium", "redaction may remove semantics required for exact replay")
        return TransformResult(
            transformed=obj.with_fields(fields, provenance_note=self.name),
            residue_report=residue,
            explanation="Redacted identifier-bearing fields for authorized analysis.",
        )


@dataclass(frozen=True)
class BucketTimingOperator:
    name: str = "bucket_timing"
    risk_level: str = "medium"
    preserves_semantics: bool = True
    bucket_ms: int = 100

    def apply(self, obj: SurfaceObject) -> TransformResult:
        timing = dict(obj.timing_model)
        changed = 0
        for key in ("interarrival_ms", "delta_ms", "duration_ms", "jitter_ms"):
            if key in timing:
                try:
                    raw = float(timing[key])
                    timing[key] = int(raw // self.bucket_ms) * self.bucket_ms
                    changed += 1
                except Exception:
                    continue
        residue = ResidueReport().add("timing", "medium" if changed else "low", f"bucketed {changed} timing fields")
        return TransformResult(
            transformed=obj.with_timing(timing, provenance_note=self.name),
            residue_report=residue,
            explanation="Bucketed timing values to analyze timing-surface stability.",
        )
