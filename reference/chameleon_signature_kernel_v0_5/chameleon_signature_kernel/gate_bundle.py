from __future__ import annotations

from dataclasses import dataclass, field

from .policy import PolicyDecision
from .residue_report import ResidueReport
from .spectral_signature import SpectralSignature
from .target_profile import TargetProfile


@dataclass(frozen=True)
class GateVector:
    decision: str
    global_distance: float
    dimension_distances: dict[str, float]
    failed_dimensions: tuple[str, ...] = field(default_factory=tuple)
    reasons: tuple[str, ...] = field(default_factory=tuple)


class GateBundle:
    def evaluate(
        self,
        *,
        source_signature: SpectralSignature,
        transformed_signature: SpectralSignature,
        target: TargetProfile,
        residue_report: ResidueReport,
        policy_decision: PolicyDecision | None = None,
    ) -> GateVector:
        if policy_decision and policy_decision.decision != "PASS":
            return GateVector(
                decision="FAIL",
                global_distance=source_signature.global_distance(transformed_signature),
                dimension_distances=transformed_signature.distance_by_dimension(target.signature),
                failed_dimensions=("policy",),
                reasons=(policy_decision.reason,),
            )

        dimension_distances = transformed_signature.distance_by_dimension(target.signature)
        global_distance = transformed_signature.global_distance(target.signature)
        failed = tuple(
            dim for dim, distance in dimension_distances.items()
            if distance > target.dimension_tolerances.get(dim, target.global_tolerance)
        )

        reasons: list[str] = []
        if failed:
            reasons.append(f"distance_exceeds_tolerance:{','.join(failed)}")
        if global_distance > target.global_tolerance:
            reasons.append("global_distance_exceeds_tolerance")
        if residue_report.has_forbidden(target.forbidden_residue_surfaces):
            reasons.append("critical_residue_surface")
        elif residue_report.externalize(surfaces=target.residue_externalization_surfaces):
            reasons.append("residue_externalized")

        if "critical_residue_surface" in reasons:
            decision = "FAIL"
        elif failed or len(reasons) > 0 or residue_report.max_severity() in {"medium", "high", "critical"}:
            decision = "OPTIMIZE"
        else:
            decision = "PASS"

        return GateVector(
            decision=decision,
            global_distance=global_distance,
            dimension_distances=dimension_distances,
            failed_dimensions=failed,
            reasons=tuple(reasons) if reasons else ("gate_pass",),
        )
