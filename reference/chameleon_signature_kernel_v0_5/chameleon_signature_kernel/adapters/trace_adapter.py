from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Iterable

from ..objects import SurfaceObject
from ..policy import AuthorizationManifest


class TraceImportError(ValueError):
    pass


class TraceAdapter:
    """Import adapter for owned/authorized trace records.

    Supported formats are JSON arrays, JSONL, CSV, and HAR-like browser exports.
    Raw packet capture parsing is intentionally out of scope for this kernel.
    """

    def __init__(self, authorization: AuthorizationManifest):
        if not authorization.is_valid_for("offline_analysis"):
            raise TraceImportError("valid trace analysis authorization is required")
        self.authorization = authorization

    def from_records(self, records: Iterable[dict[str, Any]], *, media_type: str = "application/trace+json") -> list[SurfaceObject]:
        objects = []
        for index, record in enumerate(records):
            if not isinstance(record, dict):
                raise TraceImportError(f"record {index} is not a dictionary")
            timing_model = {}
            for key in ("interarrival_ms", "delta_ms", "duration_ms", "jitter_ms"):
                if key in record:
                    timing_model[key] = record[key]
            declared = str(record.get("protocol", record.get("declared_protocol_class", "unknown"))).lower()
            provenance = {
                "source_name": self.authorization.source_name,
                "owner_or_controller": self.authorization.owner_or_controller,
                "record_index": index,
                "authorization_evidence_ref": self.authorization.evidence_ref,
            }
            ordering = tuple(str(k) for k in record.keys())
            objects.append(SurfaceObject(
                media_type=media_type,
                fields=dict(record),
                ordering=ordering,
                timing_model=timing_model,
                declared_protocol_class=declared,
                provenance=provenance,
            ))
        return objects

    def from_json_file(self, path: str | Path) -> list[SurfaceObject]:
        path = Path(path)
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and "log" in data:
            return self.from_har_dict(data)
        if isinstance(data, dict) and "records" in data:
            data = data["records"]
        if not isinstance(data, list):
            raise TraceImportError("JSON trace file must contain a list or {'records': [...]}")
        return self.from_records(data)

    def from_jsonl_file(self, path: str | Path) -> list[SurfaceObject]:
        records = []
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            if line.strip():
                records.append(json.loads(line))
        return self.from_records(records)

    def from_csv_file(self, path: str | Path) -> list[SurfaceObject]:
        with Path(path).open("r", encoding="utf-8", newline="") as f:
            return self.from_records(list(csv.DictReader(f)), media_type="text/csv+trace")

    def from_har_dict(self, data: dict[str, Any]) -> list[SurfaceObject]:
        try:
            entries = data["log"]["entries"]
        except Exception as exc:
            raise TraceImportError("HAR-like data must contain log.entries") from exc

        records = []
        for entry in entries:
            request = entry.get("request", {})
            response = entry.get("response", {})
            headers = {h.get("name", ""): h.get("value", "") for h in request.get("headers", []) if h.get("name")}
            records.append({
                "protocol": "http",
                "method": request.get("method", "UNKNOWN"),
                "url": request.get("url", ""),
                "headers": headers,
                "status": response.get("status", "unknown"),
                "duration_ms": entry.get("time", -1),
            })
        return self.from_records(records, media_type="application/har+json")
