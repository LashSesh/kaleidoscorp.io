from __future__ import annotations

import json
from dataclasses import asdict, dataclass, replace
from hashlib import sha256
from statistics import mean
from typing import Any, Sequence

from .kernel import ChameleonKernel
from .objects import SurfaceObject
from .policy import AuthorizationManifest
from .target_profile import OperationalMask, TargetProfile
from .transform_operator import TransformOperator


def _stable_digest(payload: Any) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return sha256(encoded.encode("utf-8")).hexdigest()


def surface_ref(obj: SurfaceObject) -> str:
    payload = {
        "media_type": obj.media_type,
        "declared_protocol_class": obj.declared_protocol_class,
        "field_names": sorted(str(key) for key in obj.fields.keys()),
        "ordering": tuple(str(key) for key in obj.ordering),
        "timing_keys": sorted(str(key) for key in obj.timing_model.keys()),
        "provenance": {
            "source": obj.provenance.get("source") or obj.provenance.get("source_name"),
            "record_id": obj.provenance.get("record_id") or obj.provenance.get("record_index"),
            "adapter": obj.provenance.get("adapter"),
        },
    }
    return _stable_digest(payload)


@dataclass(frozen=True)
class IterationCandidate:
    round_index: int
    object_index: int
    operator_name: str
    source_ref: str
    transformed_ref: str
    source_signature_digest: str
    transformed_signature_digest: str
    distance_before: float
    distance_after: float
    improvement: float
    decision: str
    top_drift_dimensions: tuple[str, ...]
    residue_ref: str | None
    selected: bool = False


@dataclass(frozen=True)
class IterationRound:
    round_index: int
    candidates: tuple[IterationCandidate, ...]
    selected_candidates: tuple[IterationCandidate, ...]
    average_distance_before: float
    average_distance_after: float
    improvement: float
    decision: str
    top_drift_dimensions: tuple[str, ...]


@dataclass(frozen=True)
class RecursiveIterationResult:
    iteration_id: str
    target_name: str
    rounds: tuple[IterationRound, ...]
    final_object_refs: tuple[str, ...]
    final_average_distance: float
    converged: bool
    stop_reason: str

    def selected_operator_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for round_result in self.rounds:
            for candidate in round_result.selected_candidates:
                counts[candidate.operator_name] = counts.get(candidate.operator_name, 0) + 1
        return counts

    def top_drift_dimensions(self) -> tuple[str, ...]:
        dimensions: list[str] = []
        for round_result in self.rounds:
            for dimension in round_result.top_drift_dimensions:
                if dimension not in dimensions:
                    dimensions.append(dimension)
        return tuple(dimensions)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class RecursiveSignatureIterator:
    """Recursive local improvement loop over signatures and transform operators."""

    def __init__(self, *, kernel: ChameleonKernel | None = None):
        self.kernel = kernel or ChameleonKernel()

    def run(
        self,
        *,
        objects: Sequence[SurfaceObject],
        operators: Sequence[TransformOperator],
        target: TargetProfile | OperationalMask,
        authorization: AuthorizationManifest | None,
        mode: str = "adapter_operation",
        max_rounds: int = 3,
        min_improvement: float = 0.000001,
    ) -> RecursiveIterationResult:
        if not objects:
            raise ValueError("at least one object is required")
        if not operators:
            raise ValueError("at least one operator is required")
        if max_rounds < 1:
            raise ValueError("max_rounds must be at least 1")

        target_profile = target.to_target_profile() if isinstance(target, OperationalMask) else target
        policy_decision = self.kernel.policy.evaluate(mode=mode, authorization=authorization)
        if policy_decision.decision != "PASS":
            raise ValueError(policy_decision.reason)

        current_objects = list(objects)
        rounds: list[IterationRound] = []
        previous_average = self._average_distance(current_objects, target_profile)
        stop_reason = "max_rounds"

        if previous_average <= target_profile.global_tolerance:
            stop_reason = "already_converged"

        for round_index in range(max_rounds):
            if stop_reason == "already_converged":
                break

            next_objects: list[SurfaceObject] = []
            round_candidates: list[IterationCandidate] = []
            selected_candidates: list[IterationCandidate] = []

            for object_index, obj in enumerate(current_objects):
                source_signature = self.kernel.signature_for(obj)
                source_report = source_signature.compare(
                    target_profile.signature,
                    dimension_tolerances=target_profile.dimension_tolerances,
                    global_tolerance=target_profile.global_tolerance,
                )
                best_candidate: IterationCandidate | None = None
                best_candidate_index: int | None = None
                best_object = obj

                for operator in operators:
                    transform_result = operator.apply(obj)
                    transformed = transform_result.transformed
                    transformed_signature = self.kernel.signature_for(transformed)
                    report = transformed_signature.compare(
                        target_profile.signature,
                        dimension_tolerances=target_profile.dimension_tolerances,
                        global_tolerance=target_profile.global_tolerance,
                    )
                    disposition = transform_result.residue_report.externalize(
                        surfaces=target_profile.residue_externalization_surfaces,
                    )
                    improvement = round(source_report.global_distance - report.global_distance, 6)
                    candidate = IterationCandidate(
                        round_index=round_index,
                        object_index=object_index,
                        operator_name=operator.name,
                        source_ref=surface_ref(obj),
                        transformed_ref=surface_ref(transformed),
                        source_signature_digest=source_signature.digest,
                        transformed_signature_digest=transformed_signature.digest,
                        distance_before=source_report.global_distance,
                        distance_after=report.global_distance,
                        improvement=improvement,
                        decision=report.decision,
                        top_drift_dimensions=report.top_dimensions,
                        residue_ref=disposition.residue_ref if disposition else None,
                    )
                    round_candidates.append(candidate)
                    if self._is_better(candidate, best_candidate):
                        best_candidate = candidate
                        best_candidate_index = len(round_candidates) - 1
                        best_object = transformed

                if best_candidate and best_candidate.improvement > min_improvement:
                    selected = replace(best_candidate, selected=True)
                    if best_candidate_index is not None:
                        round_candidates[best_candidate_index] = selected
                    selected_candidates.append(selected)
                    next_objects.append(best_object)
                else:
                    next_objects.append(obj)

            average_after = self._average_distance(next_objects, target_profile)
            improvement = round(previous_average - average_after, 6)
            top_dimensions = self._top_dimensions(next_objects, target_profile)
            decision = "PASS" if average_after <= target_profile.global_tolerance else "OPTIMIZE"
            rounds.append(
                IterationRound(
                    round_index=round_index,
                    candidates=tuple(round_candidates),
                    selected_candidates=tuple(selected_candidates),
                    average_distance_before=previous_average,
                    average_distance_after=average_after,
                    improvement=improvement,
                    decision=decision,
                    top_drift_dimensions=top_dimensions,
                )
            )

            current_objects = next_objects
            previous_average = average_after
            if average_after <= target_profile.global_tolerance:
                stop_reason = "converged"
                break
            if not selected_candidates:
                stop_reason = "no_candidate_improved"
                break
            if improvement <= min_improvement:
                stop_reason = "no_significant_improvement"
                break

        final_average = self._average_distance(current_objects, target_profile)
        payload = {
            "target": target_profile.name,
            "rounds": [asdict(round_result) for round_result in rounds],
            "final_refs": [surface_ref(obj) for obj in current_objects],
            "final_average": final_average,
            "stop_reason": stop_reason,
        }
        return RecursiveIterationResult(
            iteration_id=_stable_digest(payload),
            target_name=target_profile.name,
            rounds=tuple(rounds),
            final_object_refs=tuple(surface_ref(obj) for obj in current_objects),
            final_average_distance=final_average,
            converged=final_average <= target_profile.global_tolerance,
            stop_reason=stop_reason,
        )

    def _average_distance(self, objects: Sequence[SurfaceObject], target: TargetProfile) -> float:
        distances = [
            self.kernel.signature_for(obj).global_distance(target.signature)
            for obj in objects
        ]
        return round(mean(distances), 6)

    def _top_dimensions(self, objects: Sequence[SurfaceObject], target: TargetProfile) -> tuple[str, ...]:
        ranked: dict[str, float] = {}
        for obj in objects:
            report = self.kernel.signature_for(obj).compare(
                target.signature,
                dimension_tolerances=target.dimension_tolerances,
                global_tolerance=target.global_tolerance,
            )
            for delta in report.dimension_deltas:
                ranked[delta.dimension] = max(ranked.get(delta.dimension, 0.0), delta.distance)
        return tuple(
            dimension
            for dimension, distance in sorted(ranked.items(), key=lambda item: item[1], reverse=True)
            if distance > 0
        )[:5]

    def _is_better(self, candidate: IterationCandidate, current_best: IterationCandidate | None) -> bool:
        if current_best is None:
            return True
        if candidate.improvement != current_best.improvement:
            return candidate.improvement > current_best.improvement
        return candidate.distance_after < current_best.distance_after
