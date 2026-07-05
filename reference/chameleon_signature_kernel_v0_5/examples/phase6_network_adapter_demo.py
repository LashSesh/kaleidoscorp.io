from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from chameleon_signature_kernel import (
    AuthorizationManifest,
    ChameleonKernel,
    NetworkAdapter,
    NetworkAdapterConfig,
    NetworkRequest,
    NormalizeTraceShapeOperator,
    ProfileCorpus,
)


def main() -> None:
    authorization = AuthorizationManifest(
        source_name="owned-service",
        owner_or_controller="service-owner",
        permission_basis="operator-approved endpoint observation",
        allowed_uses=("network_observation", "adapter_operation"),
        evidence_ref="ticket://replace-with-approval",
    )
    adapter = NetworkAdapter(
        authorization,
        config=NetworkAdapterConfig(
            allowed_hosts=("example.com",),
            include_body=False,
            timeout_seconds=5.0,
        ),
    )
    obj = adapter.fetch(NetworkRequest("https://example.com/"))

    kernel = ChameleonKernel()
    normalized = NormalizeTraceShapeOperator().apply(obj).transformed
    corpus = ProfileCorpus()
    record = corpus.build_profile(
        name="example_network_observation",
        version="1.0.0",
        signatures=[kernel.signature_for(normalized)],
        tags=("network", "authorized"),
    )
    mask = record.to_operational_mask(global_tolerance=0.70)

    print(f"observed_status={obj.fields['status']}")
    print(f"body_length={obj.fields['body_length']}")
    print(f"operational_mask={mask.name}")


if __name__ == "__main__":
    main()
