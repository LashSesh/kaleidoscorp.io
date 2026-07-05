from __future__ import annotations

from dataclasses import dataclass, field

from .spectral_signature import SpectralSignature


@dataclass(frozen=True)
class OperationalMask:
    """Runtime mask used to score real adapter observations."""

    name: str
    signature: SpectralSignature
    dimension_tolerances: dict[str, float]
    global_tolerance: float
    residue_externalization_surfaces: tuple[str, ...] = ("semantic", "linkability")
    enforcement_level: str = "optimize"

    def to_target_profile(self) -> "TargetProfile":
        return TargetProfile(
            name=self.name,
            signature=self.signature,
            dimension_tolerances=dict(self.dimension_tolerances),
            global_tolerance=self.global_tolerance,
            forbidden_residue_surfaces=(),
            residue_externalization_surfaces=self.residue_externalization_surfaces,
            enforcement_level=self.enforcement_level,
        )


@dataclass(frozen=True)
class TargetProfile:
    name: str
    signature: SpectralSignature
    dimension_tolerances: dict[str, float] = field(default_factory=lambda: {
        "shape": 0.20,
        "ordering": 0.20,
        "entropy": 0.50,
        "timing": 0.75,
        "semantic": 0.20,
        "linkability": 0.20,
    })
    global_tolerance: float = 0.35
    forbidden_residue_surfaces: tuple[str, ...] = ()
    residue_externalization_surfaces: tuple[str, ...] = ("semantic", "linkability")
    enforcement_level: str = "optimize"

    def to_operational_mask(self) -> OperationalMask:
        return OperationalMask(
            name=self.name,
            signature=self.signature,
            dimension_tolerances=dict(self.dimension_tolerances),
            global_tolerance=self.global_tolerance,
            residue_externalization_surfaces=self.residue_externalization_surfaces,
            enforcement_level=self.enforcement_level,
        )
