from __future__ import annotations

from dataclasses import dataclass

from .canonicalizer import CanonicalObject
from .spectral_signature import SpectralSignature


@dataclass(frozen=True)
class ReanalysisResult:
    decision: str
    same_protocol_class: bool
    signature_stable: bool
    notes: tuple[str, ...]


def reanalyze(
    *,
    source: CanonicalObject,
    transformed: CanonicalObject,
    source_signature: SpectralSignature,
    transformed_signature: SpectralSignature,
    max_signature_drift: float = 0.50,
) -> ReanalysisResult:
    same_class = source.declared_protocol_class == transformed.declared_protocol_class
    drift = source_signature.global_distance(transformed_signature)
    stable = drift <= max_signature_drift
    notes: list[str] = [f"signature_drift={drift}"]
    if not same_class:
        notes.append("protocol_class_changed")
    if not stable:
        notes.append("signature_drift_exceeds_limit")
    decision = "PASS" if same_class and stable else "OPTIMIZE"
    return ReanalysisResult(
        decision=decision,
        same_protocol_class=same_class,
        signature_stable=stable,
        notes=tuple(notes),
    )
