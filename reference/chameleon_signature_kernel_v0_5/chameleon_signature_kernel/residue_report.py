from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256


_SEVERITY_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class Residue:
    surface: str
    severity: str
    message: str


@dataclass(frozen=True)
class ResidueDisposition:
    phase: str
    action: str
    residue_ref: str
    count: int
    max_severity: str


@dataclass(frozen=True)
class ResidueReport:
    residues: tuple[Residue, ...] = field(default_factory=tuple)

    def add(self, surface: str, severity: str, message: str) -> "ResidueReport":
        return ResidueReport(self.residues + (Residue(surface, severity, message),))

    def by_surface(self, surface: str) -> tuple[Residue, ...]:
        return tuple(r for r in self.residues if r.surface == surface)

    def has_forbidden(self, forbidden_surfaces: tuple[str, ...]) -> bool:
        return any(r.surface in forbidden_surfaces and r.severity in {"medium", "high", "critical"} for r in self.residues)

    def max_severity(self) -> str:
        result = "none"
        max_val = 0
        for residue in self.residues:
            val = _SEVERITY_ORDER.get(residue.severity, 0)
            if val > max_val:
                max_val = val
                result = residue.severity
        return result

    def externalize(
        self,
        *,
        phase: str = "post_transform",
        surfaces: tuple[str, ...] = (),
        minimum_severity: str = "medium",
    ) -> ResidueDisposition | None:
        minimum = _SEVERITY_ORDER.get(minimum_severity, 2)
        selected = tuple(
            residue
            for residue in self.residues
            if (not surfaces or residue.surface in surfaces)
            and _SEVERITY_ORDER.get(residue.severity, 0) >= minimum
        )
        if not selected:
            return None
        payload = "|".join(
            f"{residue.surface}:{residue.severity}:{residue.message}"
            for residue in selected
        )
        ref = sha256(payload.encode("utf-8")).hexdigest()
        max_severity = "none"
        for residue in selected:
            if _SEVERITY_ORDER.get(residue.severity, 0) > _SEVERITY_ORDER.get(max_severity, 0):
                max_severity = residue.severity
        return ResidueDisposition(
            phase=phase,
            action="externalized",
            residue_ref=ref,
            count=len(selected),
            max_severity=max_severity,
        )
