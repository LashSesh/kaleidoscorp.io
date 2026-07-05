from dataclasses import dataclass

from chameleon_signature_kernel import (
    AuthorizationManifest,
    ChameleonKernel,
    RecursiveSignatureIterator,
    SurfaceObject,
    TargetProfile,
)
from chameleon_signature_kernel.residue_report import ResidueReport
from chameleon_signature_kernel.transform_operator import TransformResult


def _obj(status: int) -> SurfaceObject:
    fields = {
        "protocol": "http",
        "method": "GET",
        "url": "https://example.test/status",
        "status": status,
        "headers": {"Content-Type": "application/json"},
        "response_header_order": ("Content-Type",),
        "duration_ms": 25,
        "body": {"status": status},
        "body_length": 16,
    }
    return SurfaceObject(
        media_type="application/network-observation+http",
        fields=fields,
        ordering=tuple(fields),
        timing_model={"duration_ms": 25},
        declared_protocol_class="http",
    )


@dataclass(frozen=True)
class SetStatusOperator:
    status: int
    name: str = "set_status"
    risk_level: str = "low"
    preserves_semantics: bool = True

    def apply(self, obj: SurfaceObject) -> TransformResult:
        fields = dict(obj.fields)
        fields["status"] = self.status
        fields["body"] = {"status": self.status}
        transformed = obj.with_fields(fields, provenance_note=self.name)
        residue = ResidueReport().add("semantic", "low", f"status aligned to {self.status}")
        return TransformResult(transformed=transformed, residue_report=residue, explanation="Align status for test.")


@dataclass(frozen=True)
class NoOpOperator:
    name: str = "noop"
    risk_level: str = "low"
    preserves_semantics: bool = True

    def apply(self, obj: SurfaceObject) -> TransformResult:
        return TransformResult(transformed=obj, residue_report=ResidueReport(), explanation="No operation.")


def test_recursive_iterator_selects_best_improving_candidate():
    kernel = ChameleonKernel()
    source = _obj(200)
    target_obj = _obj(404)
    target = TargetProfile(
        name="status_target",
        signature=kernel.signature_for(target_obj),
        global_tolerance=0.01,
        dimension_tolerances={"http_surface": 0.01, "body_schema": 0.01, "semantic": 0.01},
    )
    auth = AuthorizationManifest("owned", "tester", "approved", ("adapter_operation",))

    result = RecursiveSignatureIterator(kernel=kernel).run(
        objects=(source,),
        operators=(NoOpOperator(), SetStatusOperator(404)),
        target=target,
        authorization=auth,
        max_rounds=3,
    )

    assert result.rounds
    assert result.rounds[0].selected_candidates[0].operator_name == "set_status"
    assert result.rounds[0].improvement > 0
    assert result.final_average_distance < result.rounds[0].average_distance_before
    assert result.selected_operator_counts()["set_status"] == 1


def test_recursive_iterator_stops_when_no_candidate_improves():
    kernel = ChameleonKernel()
    source = _obj(200)
    target = TargetProfile(name="same", signature=kernel.signature_for(source), global_tolerance=0.01)
    auth = AuthorizationManifest("owned", "tester", "approved", ("adapter_operation",))

    result = RecursiveSignatureIterator(kernel=kernel).run(
        objects=(source,),
        operators=(NoOpOperator(),),
        target=target,
        authorization=auth,
        max_rounds=2,
    )

    assert result.converged is True
    assert result.stop_reason == "already_converged"
    assert result.rounds == ()
