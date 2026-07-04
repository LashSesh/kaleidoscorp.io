from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from statistics import mean
from typing import Any, Sequence

from .kernel import ChameleonEvent, ChameleonKernel
from .objects import SurfaceObject
from .policy import AuthorizationManifest, PolicyDecision
from .target_profile import OperationalMask, TargetProfile
from .transform_operator import TransformOperator


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _stable_digest(payload: Any) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return sha256(encoded.encode("utf-8")).hexdigest()


def object_ref(obj: SurfaceObject) -> str:
    """Return a stable reference without exporting raw trace fields."""
    payload = {
        "media_type": obj.media_type,
        "declared_protocol_class": obj.declared_protocol_class,
        "field_names": sorted(str(k) for k in obj.fields.keys()),
        "ordering": tuple(str(k) for k in obj.ordering),
        "timing_keys": sorted(str(k) for k in obj.timing_model.keys()),
        "provenance": {
            "source": obj.provenance.get("source") or obj.provenance.get("source_name"),
            "record_id": obj.provenance.get("record_id") or obj.provenance.get("record_index"),
            "adapter": obj.provenance.get("adapter"),
            "authorization_source": obj.provenance.get("authorization_source")
            or obj.provenance.get("authorization_evidence_ref"),
        },
    }
    return _stable_digest(payload)


@dataclass(frozen=True)
class ControlIntent:
    """Runtime intent for an adapter operation."""

    objective: str
    target_profile_name: str
    mode: str = "adapter_operation"
    requested_live_action: bool = False
    requested_network_io: bool = False
    export_level: str = "operational_plan"
    allowed_decisions: tuple[str, ...] = ("PASS", "OPTIMIZE")
    capabilities: tuple[str, ...] = ("network_observation",)
    notes: tuple[str, ...] = field(default_factory=tuple)

    @property
    def wants_network_io(self) -> bool:
        return self.requested_network_io or self.requested_live_action


@dataclass(frozen=True)
class ControlledAdapterPolicy:
    """Execution contract for adapter operation planning."""

    allow_network_io: bool = True
    allowed_modes: tuple[str, ...] = (
        "adapter_operation",
        "network_observation",
        "network_reanalysis",
        "offline_analysis",
        "audit_export",
        "policy_planning",
    )
    allowed_export_levels: tuple[str, ...] = (
        "operational_plan",
        "effectiveness_feedback",
        "audit_summary",
        "machine_plan",
    )
    unsupported_capabilities: tuple[str, ...] = (
        "live_packet_manipulation",
        "proxy_or_vpn_control",
        "credential_use",
        "detector_bypass",
        "covert_channel",
        "packet_injection",
    )
    unsupported_objective_terms: tuple[str, ...] = (
        "detector_bypass",
        "stealth_bypass",
        "avoid_detection",
        "disable_detection",
        "covert_channel",
        "packet_injection",
        "rotate_proxy",
        "spoof_live_tls",
    )

    @property
    def blocked_capabilities(self) -> tuple[str, ...]:
        return self.unsupported_capabilities

    def evaluate_intent(self, intent: ControlIntent) -> PolicyDecision:
        if intent.mode not in self.allowed_modes:
            return PolicyDecision("FAIL", f"adapter_mode_not_supported:{intent.mode}")
        if intent.export_level not in self.allowed_export_levels:
            return PolicyDecision("FAIL", f"export_level_not_supported:{intent.export_level}")
        if intent.wants_network_io and not self.allow_network_io:
            return PolicyDecision("OPTIMIZE", "network_io_requires_adapter_configuration")

        requested = set(intent.capabilities)
        unsupported = sorted(requested.intersection(self.unsupported_capabilities))
        if unsupported:
            return PolicyDecision("FAIL", f"unsupported_capability:{','.join(unsupported)}")

        objective_l = intent.objective.lower().replace(" ", "_")
        for term in self.unsupported_objective_terms:
            if term in objective_l:
                return PolicyDecision("FAIL", f"unsupported_objective:{term}")

        return PolicyDecision("PASS", "adapter_execution_contract_pass")


@dataclass(frozen=True)
class ControlPlanStep:
    step_id: str
    object_ref: str
    operator_name: str
    target_name: str
    gate_decision: str
    operation_decision: str
    failed_dimensions: tuple[str, ...]
    reasons: tuple[str, ...]
    residue_phase: str
    residue_ref: str | None
    optimization_state: str
    signature_distance: float
    top_drift_dimensions: tuple[str, ...]
    signature_decision: str
    replay_effectiveness: float
    replay_decision: str


@dataclass(frozen=True)
class ControlPlan:
    plan_id: str
    created_at: str
    intent: ControlIntent
    adapter_policy_decision: PolicyDecision
    target_name: str
    steps: tuple[ControlPlanStep, ...]
    overall_decision: str
    blocked_capabilities: tuple[str, ...]
    feedback_score: float
    notes: tuple[str, ...] = field(default_factory=tuple)

    def decision_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for step in self.steps:
            counts[step.gate_decision] = counts.get(step.gate_decision, 0) + 1
        return counts


@dataclass(frozen=True)
class AdapterExportBundle:
    """Serializable export bundle for control UIs or adapter orchestrators."""

    export_id: str
    created_at: str
    plan: ControlPlan
    audit_summary: dict[str, Any]
    execution_contract: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        def convert(value: Any) -> Any:
            if is_dataclass(value):
                return {k: convert(v) for k, v in asdict(value).items()}
            if isinstance(value, tuple):
                return [convert(v) for v in value]
            if isinstance(value, list):
                return [convert(v) for v in value]
            if isinstance(value, dict):
                return {str(k): convert(v) for k, v in value.items()}
            return value

        return convert(self)

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True, default=str)

    def write_json(self, path: str | Path) -> Path:
        path = Path(path)
        path.write_text(self.to_json() + "\n", encoding="utf-8")
        return path


class ControlledAdapterFramework:
    """Build executable adapter plans from kernel evaluations and network observations."""

    def __init__(
        self,
        *,
        kernel: ChameleonKernel | None = None,
        adapter_policy: ControlledAdapterPolicy | None = None,
    ) -> None:
        self.kernel = kernel or ChameleonKernel()
        self.adapter_policy = adapter_policy or ControlledAdapterPolicy()

    def build_plan(
        self,
        *,
        intent: ControlIntent,
        objects: Sequence[SurfaceObject],
        operators: Sequence[TransformOperator],
        target: TargetProfile | OperationalMask,
        authorization: AuthorizationManifest | None,
    ) -> ControlPlan:
        execution_decision = self.adapter_policy.evaluate_intent(intent)
        target_profile = target.to_target_profile() if isinstance(target, OperationalMask) else target

        steps: list[ControlPlanStep] = []
        if execution_decision.decision == "PASS":
            kernel_mode = self._kernel_mode_for(intent)
            for obj_index, obj in enumerate(objects):
                for op_index, operator in enumerate(operators):
                    event = self.kernel.evaluate(
                        obj=obj,
                        operator=operator,
                        target=target_profile,
                        authorization=authorization,
                        mode=kernel_mode,
                    )
                    step = self._event_to_step(
                        event=event,
                        obj=obj,
                        obj_index=obj_index,
                        op_index=op_index,
                    )
                    steps.append(step)

        overall = self._overall_decision(execution_decision, steps)
        feedback_score = round(mean(step.replay_effectiveness for step in steps), 6) if steps else 0.0

        plan_payload = {
            "intent": asdict(intent),
            "target": target_profile.name,
            "steps": [asdict(s) for s in steps],
            "execution": asdict(execution_decision),
            "unsupported": self.adapter_policy.unsupported_capabilities,
            "feedback_score": feedback_score,
        }

        return ControlPlan(
            plan_id=_stable_digest(plan_payload),
            created_at=_now(),
            intent=intent,
            adapter_policy_decision=execution_decision,
            target_name=target_profile.name,
            steps=tuple(steps),
            overall_decision=overall,
            blocked_capabilities=self.adapter_policy.unsupported_capabilities,
            feedback_score=feedback_score,
            notes=(
                "network_observation_supported_by_configured_adapters",
                "residue_details_externalized",
                "replay_feedback_enabled",
            ),
        )

    def export_bundle(self, plan: ControlPlan) -> AdapterExportBundle:
        audit_summary = {
            "plan_id": plan.plan_id,
            "overall_decision": plan.overall_decision,
            "decision_counts": plan.decision_counts(),
            "step_count": len(plan.steps),
            "target_name": plan.target_name,
            "operator_names": sorted({step.operator_name for step in plan.steps}),
            "feedback_score": plan.feedback_score,
            "top_drift_dimensions": sorted({dim for step in plan.steps for dim in step.top_drift_dimensions}),
            "unsupported_capabilities": list(plan.blocked_capabilities),
        }
        execution_contract = {
            "execution": "supported_for_configured_adapters",
            "network_observation": "supported",
            "network_mutation": "unsupported",
            "proxy_vpn_control": "unsupported",
            "detector_bypass": "unsupported",
            "raw_trace_export": "not_included",
            "residue_details": "externalized_by_reference",
            "allowed_use": "authorized_adapter_operation",
        }
        export_payload = {
            "plan_id": plan.plan_id,
            "audit_summary": audit_summary,
            "execution_contract": execution_contract,
        }
        return AdapterExportBundle(
            export_id=_stable_digest(export_payload),
            created_at=_now(),
            plan=plan,
            audit_summary=audit_summary,
            execution_contract=execution_contract,
        )

    def _event_to_step(
        self,
        *,
        event: ChameleonEvent,
        obj: SurfaceObject,
        obj_index: int,
        op_index: int,
    ) -> ControlPlanStep:
        disposition = event.residue_report.externalize()
        if event.gate_vector.decision == "PASS":
            optimization_state = "ready"
        elif event.gate_vector.decision == "OPTIMIZE":
            optimization_state = "improve"
        else:
            optimization_state = "blocked"

        return ControlPlanStep(
            step_id=f"step-{obj_index:03d}-{op_index:03d}",
            object_ref=object_ref(obj),
            operator_name=event.operator_name,
            target_name=event.target_name,
            gate_decision=event.gate_vector.decision,
            operation_decision=event.policy_decision.decision,
            failed_dimensions=event.gate_vector.failed_dimensions,
            reasons=event.gate_vector.reasons,
            residue_phase=disposition.phase if disposition else "none",
            residue_ref=disposition.residue_ref if disposition else None,
            optimization_state=optimization_state,
            signature_distance=event.signature_report.global_distance,
            top_drift_dimensions=event.signature_report.top_dimensions,
            signature_decision=event.signature_report.decision,
            replay_effectiveness=event.replay_feedback.effectiveness_score,
            replay_decision=event.replay_feedback.decision,
        )

    def _overall_decision(self, execution_decision: PolicyDecision, steps: Sequence[ControlPlanStep]) -> str:
        if execution_decision.decision == "FAIL":
            return "FAIL"
        if execution_decision.decision == "OPTIMIZE":
            return "OPTIMIZE"
        if not steps:
            return "OPTIMIZE"
        decisions = {s.gate_decision for s in steps}
        if "FAIL" in decisions:
            return "FAIL"
        if "OPTIMIZE" in decisions:
            return "OPTIMIZE"
        return "PASS"

    def _kernel_mode_for(self, intent: ControlIntent) -> str:
        if intent.mode in {"network_observation", "network_reanalysis"} or intent.wants_network_io:
            return "network_observation"
        if intent.mode == "adapter_operation":
            return "adapter_operation"
        return "offline_analysis"
