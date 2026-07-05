from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha256
from math import sqrt

from .feature_space import FeatureVector


def _digest_dimension(payload: dict[str, float | str]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return sha256(encoded.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class SignatureDimensionDelta:
    dimension: str
    distance: float
    tolerance: float
    decision: str
    left_digest: str
    right_digest: str


@dataclass(frozen=True)
class SignatureComparisonReport:
    left_digest: str
    right_digest: str
    global_distance: float
    global_tolerance: float
    decision: str
    dimension_deltas: tuple[SignatureDimensionDelta, ...]
    top_dimensions: tuple[str, ...]
    shared_dimensions: tuple[str, ...]
    missing_left: tuple[str, ...]
    missing_right: tuple[str, ...]

    def decision_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for delta in self.dimension_deltas:
            counts[delta.decision] = counts.get(delta.decision, 0) + 1
        return counts


@dataclass(frozen=True)
class SpectralSignature:
    dimensions: dict[str, dict[str, float | str]]
    digest: str

    @classmethod
    def from_features(cls, features: FeatureVector) -> "SpectralSignature":
        dims = features.as_dimensions()
        encoded = json.dumps(dims, sort_keys=True, separators=(",", ":"), default=str)
        return cls(dimensions=dims, digest=sha256(encoded.encode("utf-8")).hexdigest())

    def distance_by_dimension(self, other: "SpectralSignature") -> dict[str, float]:
        out: dict[str, float] = {}
        for dim in set(self.dimensions) | set(other.dimensions):
            left = self.dimensions.get(dim, {})
            right = other.dimensions.get(dim, {})
            numeric_total = 0.0
            numeric_count = 0
            cat_total = 0.0
            cat_count = 0
            for key in set(left) | set(right):
                a = left.get(key)
                b = right.get(key)
                if isinstance(a, (int, float)) and isinstance(b, (int, float)):
                    numeric_total += float(a - b) ** 2
                    numeric_count += 1
                else:
                    cat_total += 0.0 if str(a) == str(b) else 1.0
                    cat_count += 1
            numeric_distance = sqrt(numeric_total) / max(1, numeric_count)
            categorical_distance = cat_total / max(1, cat_count) if cat_count else 0.0
            out[dim] = round(numeric_distance + categorical_distance, 6)
        return out

    def global_distance(self, other: "SpectralSignature") -> float:
        distances = self.distance_by_dimension(other)
        return round(sum(distances.values()) / max(1, len(distances)), 6)

    def compare(
        self,
        other: "SpectralSignature",
        *,
        dimension_tolerances: dict[str, float] | None = None,
        global_tolerance: float = 0.35,
        top_n: int = 5,
    ) -> SignatureComparisonReport:
        dimension_tolerances = dimension_tolerances or {}
        distances = self.distance_by_dimension(other)
        deltas: list[SignatureDimensionDelta] = []
        for dimension in sorted(distances):
            tolerance = dimension_tolerances.get(dimension, global_tolerance)
            distance = distances[dimension]
            deltas.append(
                SignatureDimensionDelta(
                    dimension=dimension,
                    distance=distance,
                    tolerance=tolerance,
                    decision="PASS" if distance <= tolerance else "OPTIMIZE",
                    left_digest=_digest_dimension(self.dimensions.get(dimension, {})),
                    right_digest=_digest_dimension(other.dimensions.get(dimension, {})),
                )
            )
        global_distance = self.global_distance(other)
        top_dimensions = tuple(
            delta.dimension
            for delta in sorted(deltas, key=lambda item: item.distance, reverse=True)[:top_n]
            if delta.distance > 0
        )
        left_dims = set(self.dimensions)
        right_dims = set(other.dimensions)
        return SignatureComparisonReport(
            left_digest=self.digest,
            right_digest=other.digest,
            global_distance=global_distance,
            global_tolerance=global_tolerance,
            decision="PASS" if global_distance <= global_tolerance and all(delta.decision == "PASS" for delta in deltas) else "OPTIMIZE",
            dimension_deltas=tuple(deltas),
            top_dimensions=top_dimensions,
            shared_dimensions=tuple(sorted(left_dims.intersection(right_dims))),
            missing_left=tuple(sorted(right_dims.difference(left_dims))),
            missing_right=tuple(sorted(left_dims.difference(right_dims))),
        )
