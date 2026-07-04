from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from chameleon_signature_kernel import (
    AuthorizationManifest,
    ChameleonKernel,
    RecursiveSignatureIterator,
    SurfaceObject,
    TargetProfile,
)
from chameleon_signature_kernel.residue_report import ResidueReport
from chameleon_signature_kernel.transform_operator import TransformResult


def surface(status: int) -> SurfaceObject:
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
class AlignStatus:
    status: int
    name: str = "align_status"
    risk_level: str = "low"
    preserves_semantics: bool = True

    def apply(self, obj: SurfaceObject) -> TransformResult:
        fields = dict(obj.fields)
        fields["status"] = self.status
        fields["body"] = {"status": self.status}
        return TransformResult(
            transformed=obj.with_fields(fields, provenance_note=self.name),
            residue_report=ResidueReport().add("semantic", "low", "status aligned for iteration demo"),
            explanation="Align status for recursive signature iteration.",
        )


def main() -> None:
    kernel = ChameleonKernel()
    source = surface(200)
    target_surface = surface(404)
    target = TargetProfile(
        name="recursive_status_target",
        signature=kernel.signature_for(target_surface),
        global_tolerance=0.01,
        dimension_tolerances={"http_surface": 0.01, "body_schema": 0.01, "semantic": 0.01},
    )
    auth = AuthorizationManifest("owned-demo", "operator", "authorized demo", ("adapter_operation",))
    result = RecursiveSignatureIterator(kernel=kernel).run(
        objects=(source,),
        operators=(AlignStatus(404),),
        target=target,
        authorization=auth,
        max_rounds=3,
    )

    print(f"iteration_id={result.iteration_id[:16]}")
    print(f"rounds={len(result.rounds)} stop={result.stop_reason}")
    print(f"converged={result.converged} final_distance={result.final_average_distance}")
    print(f"selected={result.selected_operator_counts()}")
    print(f"top_drift={list(result.top_drift_dimensions())}")


if __name__ == "__main__":
    main()
