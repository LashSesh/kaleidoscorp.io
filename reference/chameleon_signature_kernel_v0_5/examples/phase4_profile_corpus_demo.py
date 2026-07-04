from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from chameleon_signature_kernel import (
    AuthorizationManifest,
    BucketTimingOperator,
    ChameleonKernel,
    NormalizeTraceShapeOperator,
    ProfileCorpus,
    ProfileStore,
)
from chameleon_signature_kernel.adapters.trace_adapter import TraceAdapter


def main() -> None:
    authorization = AuthorizationManifest(
        source_name="local_authorized_trace_fixture",
        owner_or_controller="lab-owner",
        permission_basis="owned synthetic adapter fixtures",
        evidence_ref="demo://phase4",
    )

    adapter = TraceAdapter(authorization)

    browser_like_records = [
        {"protocol": "http", "method": "GET", "url": "/a", "status": 200, "duration_ms": 120, "headers": {"accept": "*/*"}},
        {"protocol": "http", "method": "GET", "url": "/b", "status": 200, "duration_ms": 140, "headers": {"accept": "*/*"}},
    ]
    api_like_records = [
        {"protocol": "http", "method": "POST", "url": "/v1/items", "status": 201, "duration_ms": 220, "headers": {"content-type": "application/json"}, "body": {"ok": True}},
        {"protocol": "http", "method": "POST", "url": "/v1/items", "status": 201, "duration_ms": 260, "headers": {"content-type": "application/json"}, "body": {"ok": False}},
    ]
    drifted_api_records = [
        {"protocol": "http", "method": "POST", "url": "/v2/items", "status": 500, "duration_ms": 950, "headers": {"content-type": "application/json", "cookie": "demo"}, "body": {"ok": False, "error": "x"}},
    ]

    kernel = ChameleonKernel()
    normalizer = NormalizeTraceShapeOperator()
    bucket_timing = BucketTimingOperator(bucket_ms=250)

    browser_objects = [normalizer.apply(obj).transformed for obj in adapter.from_records(browser_like_records)]
    api_objects = [normalizer.apply(obj).transformed for obj in adapter.from_records(api_like_records)]
    drifted_objects = [bucket_timing.apply(normalizer.apply(obj).transformed).transformed for obj in adapter.from_records(drifted_api_records)]

    browser_sigs = [kernel.signature_for(obj) for obj in browser_objects]
    api_sigs = [kernel.signature_for(obj) for obj in api_objects]
    drifted_sigs = [kernel.signature_for(obj) for obj in drifted_objects]

    corpus = ProfileCorpus()
    browser = corpus.build_profile(name="browser_like_http", version="1.0.0", signatures=browser_sigs, tags=("synthetic", "http"))
    api = corpus.build_profile(name="api_like_http", version="1.0.0", signatures=api_sigs, tags=("synthetic", "http"))
    drifted = corpus.build_profile(
        name="api_like_http",
        version="1.1.0",
        signatures=drifted_sigs,
        tags=("synthetic", "http", "drifted"),
        parent_digest=api.digest,
    )

    nearest = corpus.nearest(drifted.signature, k=2)
    drift = corpus.drift_report(baseline=api, candidate=drifted)
    clusters = corpus.cluster(threshold=0.45)

    with TemporaryDirectory() as tmp:
        store = ProfileStore(Path(tmp) / "profiles.json")
        store.save(corpus)
        loaded = store.load()

    print(f"profiles={len(corpus.records)} loaded={len(loaded.records)}")
    print(f"nearest={[n.right_name + ':' + str(n.global_distance) for n in nearest]}")
    print(f"drift_decision={drift.decision} drifted_dimensions={list(drift.drifted_dimensions)}")
    print(f"clusters={[c.members for c in clusters]}")
    print(f"operational_mask={browser.to_operational_mask().name}")


if __name__ == "__main__":
    main()
