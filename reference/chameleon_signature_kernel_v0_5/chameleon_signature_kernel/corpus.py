from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from statistics import mean, pstdev
from typing import Any, Iterable

from .spectral_signature import SpectralSignature
from .target_profile import OperationalMask, TargetProfile


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _digest_payload(payload: Any) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return sha256(encoded.encode("utf-8")).hexdigest()


def _mode(values: list[str]) -> str:
    if not values:
        return "unknown"
    counts: dict[str, int] = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]


@dataclass(frozen=True)
class DimensionStats:
    """Per-dimension stability information for a corpus profile."""

    numeric_mean: dict[str, float] = field(default_factory=dict)
    numeric_stddev: dict[str, float] = field(default_factory=dict)
    categorical_mode: dict[str, str] = field(default_factory=dict)
    categorical_cardinality: dict[str, int] = field(default_factory=dict)

    def as_signature_dimensions(self) -> dict[str, float | str]:
        merged: dict[str, float | str] = {}
        merged.update({k: round(v, 6) for k, v in self.numeric_mean.items()})
        merged.update(self.categorical_mode)
        return merged


@dataclass(frozen=True)
class SignatureProfileRecord:
    """Versioned centroid profile derived from authorized signatures."""

    name: str
    version: str
    signature: SpectralSignature
    dimension_stats: dict[str, DimensionStats]
    sample_count: int
    tags: tuple[str, ...] = field(default_factory=tuple)
    created_at: str = field(default_factory=_now)
    parent_digest: str | None = None
    notes: tuple[str, ...] = field(default_factory=tuple)

    @property
    def digest(self) -> str:
        payload = {
            "name": self.name,
            "version": self.version,
            "signature_digest": self.signature.digest,
            "sample_count": self.sample_count,
            "tags": self.tags,
            "parent_digest": self.parent_digest,
        }
        return _digest_payload(payload)

    def to_target_profile(
        self,
        *,
        global_tolerance: float = 0.35,
        dimension_tolerances: dict[str, float] | None = None,
        forbidden_residue_surfaces: tuple[str, ...] = (),
    ) -> TargetProfile:
        mask = self.to_operational_mask(
            global_tolerance=global_tolerance,
            dimension_tolerances=dimension_tolerances,
        )
        target = mask.to_target_profile()
        if not forbidden_residue_surfaces:
            return target
        return TargetProfile(
            name=target.name,
            signature=target.signature,
            dimension_tolerances=target.dimension_tolerances,
            global_tolerance=target.global_tolerance,
            forbidden_residue_surfaces=forbidden_residue_surfaces,
            residue_externalization_surfaces=target.residue_externalization_surfaces,
            enforcement_level=target.enforcement_level,
        )

    def to_operational_mask(
        self,
        *,
        global_tolerance: float = 0.35,
        dimension_tolerances: dict[str, float] | None = None,
        residue_externalization_surfaces: tuple[str, ...] = ("semantic", "linkability"),
    ) -> OperationalMask:
        return OperationalMask(
            name=f"{self.name}@{self.version}",
            signature=self.signature,
            dimension_tolerances=dimension_tolerances or {
                "shape": 0.20,
                "ordering": 0.25,
                "entropy": 0.50,
                "timing": 0.75,
                "semantic": 0.25,
                "linkability": 0.20,
            },
            global_tolerance=global_tolerance,
            residue_externalization_surfaces=residue_externalization_surfaces,
        )


@dataclass(frozen=True)
class ProfileDistance:
    left_name: str
    right_name: str
    left_digest: str
    right_digest: str
    global_distance: float
    dimension_distances: dict[str, float]


@dataclass(frozen=True)
class DriftReport:
    baseline_name: str
    candidate_name: str
    baseline_digest: str
    candidate_digest: str
    decision: str
    global_distance: float
    dimension_distances: dict[str, float]
    drifted_dimensions: tuple[str, ...]
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class ClusterReport:
    cluster_id: int
    members: tuple[str, ...]
    member_digests: tuple[str, ...]
    notes: tuple[str, ...] = field(default_factory=tuple)


class ProfileCorpus:
    """Corpus of versioned signature profiles.

    This corpus stores centroid signatures and profile metadata. It does not
    perform network I/O, packet transformation, or evasion.
    """

    def __init__(self, records: Iterable[SignatureProfileRecord] | None = None):
        self._records: list[SignatureProfileRecord] = list(records or [])

    @property
    def records(self) -> tuple[SignatureProfileRecord, ...]:
        return tuple(self._records)

    def add_record(self, record: SignatureProfileRecord) -> SignatureProfileRecord:
        if any(r.name == record.name and r.version == record.version for r in self._records):
            raise ValueError(f"profile already exists: {record.name}@{record.version}")
        self._records.append(record)
        return record

    def build_profile(
        self,
        *,
        name: str,
        version: str,
        signatures: Iterable[SpectralSignature],
        tags: tuple[str, ...] = (),
        parent_digest: str | None = None,
        notes: tuple[str, ...] = (),
    ) -> SignatureProfileRecord:
        signatures = list(signatures)
        if not signatures:
            raise ValueError("at least one signature is required to build a profile")
        centroid_dimensions, stats = self._centroid(signatures)
        digest = _digest_payload(centroid_dimensions)
        signature = SpectralSignature(dimensions=centroid_dimensions, digest=digest)
        record = SignatureProfileRecord(
            name=name,
            version=version,
            signature=signature,
            dimension_stats=stats,
            sample_count=len(signatures),
            tags=tags,
            parent_digest=parent_digest,
            notes=notes,
        )
        return self.add_record(record)

    def get(self, name: str, version: str | None = None) -> SignatureProfileRecord:
        matches = [r for r in self._records if r.name == name and (version is None or r.version == version)]
        if not matches:
            raise KeyError(f"profile not found: {name}@{version or '*'}")
        if version is None:
            return sorted(matches, key=lambda r: r.created_at)[-1]
        return matches[0]

    def nearest(self, signature: SpectralSignature, *, k: int = 3) -> tuple[ProfileDistance, ...]:
        distances = [
            ProfileDistance(
                left_name="candidate",
                right_name=f"{record.name}@{record.version}",
                left_digest=signature.digest,
                right_digest=record.digest,
                global_distance=signature.global_distance(record.signature),
                dimension_distances=signature.distance_by_dimension(record.signature),
            )
            for record in self._records
        ]
        return tuple(sorted(distances, key=lambda d: d.global_distance)[:k])

    def pairwise_distances(self) -> tuple[ProfileDistance, ...]:
        out: list[ProfileDistance] = []
        records = self._records
        for i, left in enumerate(records):
            for right in records[i + 1:]:
                out.append(ProfileDistance(
                    left_name=f"{left.name}@{left.version}",
                    right_name=f"{right.name}@{right.version}",
                    left_digest=left.digest,
                    right_digest=right.digest,
                    global_distance=left.signature.global_distance(right.signature),
                    dimension_distances=left.signature.distance_by_dimension(right.signature),
                ))
        return tuple(out)

    def drift_report(
        self,
        *,
        baseline: SignatureProfileRecord,
        candidate: SignatureProfileRecord,
        global_tolerance: float = 0.35,
        dimension_tolerances: dict[str, float] | None = None,
    ) -> DriftReport:
        dimension_tolerances = dimension_tolerances or {
            "shape": 0.20,
            "ordering": 0.25,
            "entropy": 0.50,
            "timing": 0.75,
            "semantic": 0.25,
            "linkability": 0.20,
        }
        dimension_distances = candidate.signature.distance_by_dimension(baseline.signature)
        global_distance = candidate.signature.global_distance(baseline.signature)
        drifted = tuple(
            dim for dim, distance in dimension_distances.items()
            if distance > dimension_tolerances.get(dim, global_tolerance)
        )
        reasons: list[str] = []
        if global_distance > global_tolerance:
            reasons.append("global_distance_exceeds_tolerance")
        if drifted:
            reasons.append(f"dimension_drift:{','.join(sorted(drifted))}")
        decision = "PASS" if not reasons else ("OPTIMIZE" if global_distance <= global_tolerance * 3 else "FAIL")
        return DriftReport(
            baseline_name=f"{baseline.name}@{baseline.version}",
            candidate_name=f"{candidate.name}@{candidate.version}",
            baseline_digest=baseline.digest,
            candidate_digest=candidate.digest,
            decision=decision,
            global_distance=global_distance,
            dimension_distances=dimension_distances,
            drifted_dimensions=tuple(sorted(drifted)),
            reasons=tuple(reasons) if reasons else ("no_drift",),
        )

    def cluster(self, *, threshold: float = 0.35) -> tuple[ClusterReport, ...]:
        """Simple connected-component clustering by centroid distance."""
        records = list(self._records)
        visited: set[int] = set()
        clusters: list[ClusterReport] = []

        for start in range(len(records)):
            if start in visited:
                continue
            stack = [start]
            component: list[int] = []
            visited.add(start)
            while stack:
                idx = stack.pop()
                component.append(idx)
                for j, other in enumerate(records):
                    if j in visited:
                        continue
                    distance = records[idx].signature.global_distance(other.signature)
                    if distance <= threshold:
                        visited.add(j)
                        stack.append(j)
            members = tuple(f"{records[i].name}@{records[i].version}" for i in sorted(component))
            digests = tuple(records[i].digest for i in sorted(component))
            clusters.append(ClusterReport(
                cluster_id=len(clusters),
                members=members,
                member_digests=digests,
                notes=(f"threshold={threshold}",),
            ))
        return tuple(clusters)

    @staticmethod
    def _centroid(signatures: list[SpectralSignature]) -> tuple[dict[str, dict[str, float | str]], dict[str, DimensionStats]]:
        all_dims = sorted({dim for sig in signatures for dim in sig.dimensions.keys()})
        centroid: dict[str, dict[str, float | str]] = {}
        stats_by_dim: dict[str, DimensionStats] = {}

        for dim in all_dims:
            keys = sorted({key for sig in signatures for key in sig.dimensions.get(dim, {}).keys()})
            numeric_mean: dict[str, float] = {}
            numeric_stddev: dict[str, float] = {}
            categorical_mode: dict[str, str] = {}
            categorical_cardinality: dict[str, int] = {}

            for key in keys:
                values = [sig.dimensions.get(dim, {}).get(key) for sig in signatures if key in sig.dimensions.get(dim, {})]
                numeric_values = [float(v) for v in values if isinstance(v, (int, float))]
                if numeric_values and len(numeric_values) == len(values):
                    numeric_mean[key] = round(mean(numeric_values), 6)
                    numeric_stddev[key] = round(pstdev(numeric_values), 6) if len(numeric_values) > 1 else 0.0
                else:
                    cat_values = [str(v) for v in values]
                    categorical_mode[key] = _mode(cat_values)
                    categorical_cardinality[key] = len(set(cat_values))

            stats = DimensionStats(
                numeric_mean=numeric_mean,
                numeric_stddev=numeric_stddev,
                categorical_mode=categorical_mode,
                categorical_cardinality=categorical_cardinality,
            )
            stats_by_dim[dim] = stats
            centroid[dim] = stats.as_signature_dimensions()
        return centroid, stats_by_dim


class ProfileStore:
    """JSON persistence for profile corpus records."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def save(self, corpus: ProfileCorpus) -> None:
        payload = [self._record_to_dict(record) for record in corpus.records]
        self.path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str), encoding="utf-8")

    def load(self) -> ProfileCorpus:
        if not self.path.exists():
            return ProfileCorpus()
        data = json.loads(self.path.read_text(encoding="utf-8"))
        return ProfileCorpus(self._record_from_dict(item) for item in data)

    @staticmethod
    def _record_to_dict(record: SignatureProfileRecord) -> dict[str, Any]:
        return {
            "name": record.name,
            "version": record.version,
            "signature": {
                "dimensions": record.signature.dimensions,
                "digest": record.signature.digest,
            },
            "dimension_stats": {
                dim: {
                    "numeric_mean": stats.numeric_mean,
                    "numeric_stddev": stats.numeric_stddev,
                    "categorical_mode": stats.categorical_mode,
                    "categorical_cardinality": stats.categorical_cardinality,
                }
                for dim, stats in record.dimension_stats.items()
            },
            "sample_count": record.sample_count,
            "tags": list(record.tags),
            "created_at": record.created_at,
            "parent_digest": record.parent_digest,
            "notes": list(record.notes),
        }

    @staticmethod
    def _record_from_dict(data: dict[str, Any]) -> SignatureProfileRecord:
        signature = SpectralSignature(
            dimensions=data["signature"]["dimensions"],
            digest=data["signature"]["digest"],
        )
        stats = {
            dim: DimensionStats(
                numeric_mean=dict(raw.get("numeric_mean", {})),
                numeric_stddev=dict(raw.get("numeric_stddev", {})),
                categorical_mode=dict(raw.get("categorical_mode", {})),
                categorical_cardinality=dict(raw.get("categorical_cardinality", {})),
            )
            for dim, raw in data.get("dimension_stats", {}).items()
        }
        return SignatureProfileRecord(
            name=data["name"],
            version=data["version"],
            signature=signature,
            dimension_stats=stats,
            sample_count=int(data["sample_count"]),
            tags=tuple(data.get("tags", ())),
            created_at=data.get("created_at", _now()),
            parent_digest=data.get("parent_digest"),
            notes=tuple(data.get("notes", ())),
        )
