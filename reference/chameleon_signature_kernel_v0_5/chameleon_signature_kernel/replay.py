from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha256

from .canonicalizer import CanonicalObject
from .spectral_signature import SpectralSignature


@dataclass(frozen=True)
class ReplayManifest:
    source_digest: str
    transformed_digest: str
    transformed_signature_digest: str
    operator_name: str
    kernel_version: str = "0.6.0"

    def digest(self) -> str:
        encoded = json.dumps(self.__dict__, sort_keys=True, separators=(",", ":"))
        return sha256(encoded.encode("utf-8")).hexdigest()


def build_replay_manifest(
    *,
    source: CanonicalObject,
    transformed: CanonicalObject,
    transformed_signature: SpectralSignature,
    operator_name: str,
) -> ReplayManifest:
    return ReplayManifest(
        source_digest=source.digest,
        transformed_digest=transformed.digest,
        transformed_signature_digest=transformed_signature.digest,
        operator_name=operator_name,
    )


@dataclass(frozen=True)
class ReplayFeedback:
    replay_digest: str
    target_signature_digest: str
    effectiveness_score: float
    source_distance: float
    transformed_distance: float
    optimized_dimensions: tuple[str, ...]
    decision: str
    notes: tuple[str, ...]


def build_replay_feedback(
    *,
    replay_manifest: ReplayManifest,
    source_signature: SpectralSignature,
    transformed_signature: SpectralSignature,
    target_signature: SpectralSignature,
) -> ReplayFeedback:
    source_distance = source_signature.global_distance(target_signature)
    transformed_distance = transformed_signature.global_distance(target_signature)
    if source_distance == 0 and transformed_distance == 0:
        score = 1.0
    elif source_distance == 0:
        score = 0.0
    else:
        score = max(0.0, min(1.0, (source_distance - transformed_distance) / source_distance))

    source_dims = source_signature.distance_by_dimension(target_signature)
    transformed_dims = transformed_signature.distance_by_dimension(target_signature)
    optimized = tuple(
        sorted(
            dim for dim, transformed in transformed_dims.items()
            if transformed < source_dims.get(dim, transformed)
        )
    )
    notes = [f"distance_delta={round(source_distance - transformed_distance, 6)}"]
    if not optimized and transformed_distance > source_distance:
        notes.append("transform_regressed_distance")
    elif optimized:
        notes.append("transform_improved_dimensions")

    return ReplayFeedback(
        replay_digest=replay_manifest.digest(),
        target_signature_digest=target_signature.digest,
        effectiveness_score=round(score, 6),
        source_distance=source_distance,
        transformed_distance=transformed_distance,
        optimized_dimensions=optimized,
        decision="PASS" if transformed_distance <= source_distance else "OPTIMIZE",
        notes=tuple(notes),
    )
