from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any


class AuditLedger:
    """In-memory audit buffer with explicit user-triggered export."""

    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path is not None else None
        self._entries: list[dict[str, Any]] = []

    def append(self, event: Any) -> None:
        self._entries.append(asdict(event))

    def read_all(self) -> list[dict[str, Any]]:
        return [json.loads(json.dumps(entry, sort_keys=True, default=str)) for entry in self._entries]

    def export_jsonl(self) -> str:
        return "".join(
            json.dumps(entry, sort_keys=True, default=str) + "\n"
            for entry in self._entries
        )

    def write_jsonl(self, path: str | Path | None = None) -> Path:
        destination = Path(path) if path is not None else self.path
        if destination is None:
            raise ValueError("an explicit export path is required")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(self.export_jsonl(), encoding="utf-8")
        return destination
