from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha256
from typing import Any

from .objects import SurfaceObject


@dataclass(frozen=True)
class CanonicalObject:
    media_type: str
    canonical_fields: dict[str, Any]
    declared_protocol_class: str
    digest: str


def _normalize(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k).lower(): _normalize(value[k]) for k in sorted(value, key=lambda k: str(k).lower())}
    if isinstance(value, list):
        return [_normalize(v) for v in value]
    if isinstance(value, tuple):
        return [_normalize(v) for v in value]
    if isinstance(value, str):
        return value.strip()
    return value


def canonicalize(obj: SurfaceObject) -> CanonicalObject:
    fields = _normalize(dict(obj.fields))
    payload = {
        "media_type": obj.media_type.lower().strip(),
        "declared_protocol_class": obj.declared_protocol_class.lower().strip(),
        "fields": fields,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return CanonicalObject(
        media_type=payload["media_type"],
        canonical_fields=fields,
        declared_protocol_class=payload["declared_protocol_class"],
        digest=sha256(encoded.encode("utf-8")).hexdigest(),
    )
