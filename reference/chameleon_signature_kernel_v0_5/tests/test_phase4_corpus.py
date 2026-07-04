from __future__ import annotations

from pathlib import Path

import pytest

from chameleon_signature_kernel import (
    AuthorizationManifest,
    ChameleonKernel,
    NormalizeTraceShapeOperator,
    ProfileCorpus,
    ProfileStore,
)
from chameleon_signature_kernel.adapters.trace_adapter import TraceAdapter


@pytest.fixture()
def signatures():
    authorization = AuthorizationManifest(
        source_name="unit_fixture",
        owner_or_controller="tester",
        permission_basis="owned synthetic fixtures",
    )
    adapter = TraceAdapter(authorization)
    kernel = ChameleonKernel()
    op = NormalizeTraceShapeOperator()
    records = [
        {"protocol": "http", "method": "GET", "url": "/a", "status": 200, "duration_ms": 100},
        {"protocol": "http", "method": "GET", "url": "/b", "status": 200, "duration_ms": 130},
        {"protocol": "http", "method": "POST", "url": "/v1", "status": 201, "duration_ms": 240, "body": {"ok": True}},
    ]
    objects = [op.apply(obj).transformed for obj in adapter.from_records(records)]
    return [kernel.signature_for(obj) for obj in objects]


def test_build_profile_requires_signatures():
    corpus = ProfileCorpus()
    with pytest.raises(ValueError):
        corpus.build_profile(name="empty", version="1.0.0", signatures=[])


def test_build_profile_creates_centroid(signatures):
    corpus = ProfileCorpus()
    record = corpus.build_profile(name="http_fixture", version="1.0.0", signatures=signatures[:2])
    assert record.sample_count == 2
    assert record.signature.digest
    assert "shape" in record.dimension_stats
    assert record.to_target_profile().name == "http_fixture@1.0.0"
    assert record.to_operational_mask().name == "http_fixture@1.0.0"


def test_duplicate_profile_rejected(signatures):
    corpus = ProfileCorpus()
    corpus.build_profile(name="http_fixture", version="1.0.0", signatures=signatures[:1])
    with pytest.raises(ValueError):
        corpus.build_profile(name="http_fixture", version="1.0.0", signatures=signatures[1:2])


def test_nearest_returns_profile_distances(signatures):
    corpus = ProfileCorpus()
    first = corpus.build_profile(name="first", version="1.0.0", signatures=signatures[:1])
    second = corpus.build_profile(name="second", version="1.0.0", signatures=signatures[1:])
    nearest = corpus.nearest(first.signature, k=2)
    assert nearest[0].right_name == "first@1.0.0"
    assert nearest[0].global_distance == 0.0
    assert len(nearest) == 2


def test_drift_report_pass_or_hold(signatures):
    corpus = ProfileCorpus()
    baseline = corpus.build_profile(name="profile", version="1.0.0", signatures=signatures[:2])
    candidate = corpus.build_profile(name="profile", version="1.1.0", signatures=signatures[2:])
    report = corpus.drift_report(baseline=baseline, candidate=candidate)
    assert report.decision in {"PASS", "OPTIMIZE", "FAIL"}
    assert report.baseline_name == "profile@1.0.0"
    assert report.candidate_name == "profile@1.1.0"
    assert isinstance(report.drifted_dimensions, tuple)


def test_pairwise_and_cluster(signatures):
    corpus = ProfileCorpus()
    corpus.build_profile(name="a", version="1.0.0", signatures=signatures[:1])
    corpus.build_profile(name="b", version="1.0.0", signatures=signatures[1:2])
    corpus.build_profile(name="c", version="1.0.0", signatures=signatures[2:])
    assert len(corpus.pairwise_distances()) == 3
    clusters = corpus.cluster(threshold=10.0)
    assert len(clusters) == 1
    assert len(clusters[0].members) == 3


def test_profile_store_roundtrip(tmp_path: Path, signatures):
    corpus = ProfileCorpus()
    corpus.build_profile(name="stored", version="1.0.0", signatures=signatures)
    store = ProfileStore(tmp_path / "profiles.json")
    store.save(corpus)
    loaded = store.load()
    assert len(loaded.records) == 1
    assert loaded.get("stored", "1.0.0").sample_count == 3
