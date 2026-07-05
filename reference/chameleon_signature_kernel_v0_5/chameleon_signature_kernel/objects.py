from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping


@dataclass(frozen=True)
class SurfaceObject:
    """A payload/protocol/log/trace object treated as an abstract surface."""

    media_type: str
    fields: Mapping[str, Any]
    ordering: tuple[str, ...] = field(default_factory=tuple)
    timing_model: Mapping[str, Any] = field(default_factory=dict)
    entropy_profile: Mapping[str, Any] = field(default_factory=dict)
    structure_graph: Mapping[str, Any] = field(default_factory=dict)
    declared_protocol_class: str = "unknown"
    provenance: Mapping[str, Any] = field(default_factory=dict)

    def with_fields(self, new_fields: Mapping[str, Any], *, provenance_note: str | None = None) -> "SurfaceObject":
        provenance = dict(self.provenance)
        if provenance_note:
            notes = list(provenance.get("notes", []))
            notes.append(provenance_note)
            provenance["notes"] = notes
        return SurfaceObject(
            media_type=self.media_type,
            fields=dict(new_fields),
            ordering=tuple(new_fields.keys()),
            timing_model=dict(self.timing_model),
            entropy_profile=dict(self.entropy_profile),
            structure_graph=dict(self.structure_graph),
            declared_protocol_class=self.declared_protocol_class,
            provenance=provenance,
        )

    def with_timing(self, new_timing: Mapping[str, Any], *, provenance_note: str | None = None) -> "SurfaceObject":
        provenance = dict(self.provenance)
        if provenance_note:
            notes = list(provenance.get("notes", []))
            notes.append(provenance_note)
            provenance["notes"] = notes
        return SurfaceObject(
            media_type=self.media_type,
            fields=dict(self.fields),
            ordering=tuple(self.ordering),
            timing_model=dict(new_timing),
            entropy_profile=dict(self.entropy_profile),
            structure_graph=dict(self.structure_graph),
            declared_protocol_class=self.declared_protocol_class,
            provenance=provenance,
        )
