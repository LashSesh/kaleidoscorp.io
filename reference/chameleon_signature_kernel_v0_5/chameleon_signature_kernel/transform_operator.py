from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from .objects import SurfaceObject
from .residue_report import ResidueReport


@dataclass(frozen=True)
class TransformResult:
    transformed: SurfaceObject
    residue_report: ResidueReport
    explanation: str


class TransformOperator(Protocol):
    name: str
    risk_level: str
    preserves_semantics: bool

    def apply(self, obj: SurfaceObject) -> TransformResult:
        ...
