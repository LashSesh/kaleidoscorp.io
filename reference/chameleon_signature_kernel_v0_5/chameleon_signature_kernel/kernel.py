from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .canonicalizer import canonicalize
from .feature_space import extract_features
from .gate_bundle import GateBundle, GateVector
from .objects import SurfaceObject
from .policy import AuthorizationManifest, ChameleonPolicy, PolicyDecision
from .reanalysis import ReanalysisResult, reanalyze
from .replay import ReplayFeedback, ReplayManifest, build_replay_feedback, build_replay_manifest
from .residue_report import ResidueReport
from .spectral_signature import SignatureComparisonReport, SpectralSignature
from .target_profile import TargetProfile
from .transform_operator import TransformOperator


@dataclass(frozen=True)
class ChameleonEvent:
    operator_name: str
    source_signature_digest: str
    transformed_signature_digest: str
    target_name: str
    gate_vector: GateVector
    signature_report: SignatureComparisonReport
    residue_report: ResidueReport
    replay_manifest: ReplayManifest
    replay_feedback: ReplayFeedback
    reanalysis_result: ReanalysisResult
    policy_decision: PolicyDecision


@dataclass(frozen=True)
class BatchAnalysisResult:
    events: tuple[ChameleonEvent, ...]

    def decisions(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for event in self.events:
            counts[event.gate_vector.decision] = counts.get(event.gate_vector.decision, 0) + 1
        return counts


class ChameleonKernel:
    def __init__(self, *, policy: ChameleonPolicy | None = None):
        self.policy = policy or ChameleonPolicy()
        self.gates = GateBundle()

    def signature_for(self, obj: SurfaceObject) -> SpectralSignature:
        canonical = canonicalize(obj)
        features = extract_features(canonical, obj)
        return SpectralSignature.from_features(features)

    def evaluate(
        self,
        *,
        obj: SurfaceObject,
        operator: TransformOperator,
        target: TargetProfile,
        authorization: AuthorizationManifest | None,
        mode: str = "offline_analysis",
    ) -> ChameleonEvent:
        policy_decision = self.policy.evaluate(mode=mode, authorization=authorization)

        source_canonical = canonicalize(obj)
        source_signature = SpectralSignature.from_features(extract_features(source_canonical, obj))

        transform_result = operator.apply(obj)
        transformed_canonical = canonicalize(transform_result.transformed)
        transformed_signature = SpectralSignature.from_features(
            extract_features(transformed_canonical, transform_result.transformed)
        )

        gate_vector = self.gates.evaluate(
            source_signature=source_signature,
            transformed_signature=transformed_signature,
            target=target,
            residue_report=transform_result.residue_report,
            policy_decision=policy_decision,
        )
        signature_report = transformed_signature.compare(
            target.signature,
            dimension_tolerances=target.dimension_tolerances,
            global_tolerance=target.global_tolerance,
        )

        replay_manifest = build_replay_manifest(
            source=source_canonical,
            transformed=transformed_canonical,
            transformed_signature=transformed_signature,
            operator_name=operator.name,
        )
        replay_feedback = build_replay_feedback(
            replay_manifest=replay_manifest,
            source_signature=source_signature,
            transformed_signature=transformed_signature,
            target_signature=target.signature,
        )

        reanalysis_result = reanalyze(
            source=source_canonical,
            transformed=transformed_canonical,
            source_signature=source_signature,
            transformed_signature=transformed_signature,
        )

        return ChameleonEvent(
            operator_name=operator.name,
            source_signature_digest=source_signature.digest,
            transformed_signature_digest=transformed_signature.digest,
            target_name=target.name,
            gate_vector=gate_vector,
            signature_report=signature_report,
            residue_report=transform_result.residue_report,
            replay_manifest=replay_manifest,
            replay_feedback=replay_feedback,
            reanalysis_result=reanalysis_result,
            policy_decision=policy_decision,
        )

    def analyze_batch(
        self,
        *,
        objects: Iterable[SurfaceObject],
        operator: TransformOperator,
        target: TargetProfile,
        authorization: AuthorizationManifest | None,
        mode: str = "offline_analysis",
    ) -> BatchAnalysisResult:
        return BatchAnalysisResult(tuple(
            self.evaluate(obj=obj, operator=operator, target=target, authorization=authorization, mode=mode)
            for obj in objects
        ))
