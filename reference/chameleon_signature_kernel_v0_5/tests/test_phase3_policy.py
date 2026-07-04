from chameleon_signature_kernel import AuthorizationManifest, ChameleonPolicy


def test_authorization_manifest_valid_for_offline_analysis():
    auth = AuthorizationManifest(
        source_name="owned-log",
        owner_or_controller="me",
        permission_basis="self-owned lab data",
        allowed_uses=("offline_analysis",),
    )
    assert auth.is_valid_for("offline_analysis")


def test_policy_requires_authorization():
    policy = ChameleonPolicy()
    decision = policy.evaluate(mode="offline_analysis", authorization=None)
    assert decision.decision == "FAIL"
    assert "authorization" in decision.reason


def test_policy_allows_authorized_network_observation():
    auth = AuthorizationManifest("owned-log", "me", "self-owned", ("network_observation",))
    policy = ChameleonPolicy()
    decision = policy.evaluate(mode="network_observation", authorization=auth)
    assert decision.decision == "PASS"


def test_policy_denies_unsupported_live_mutation():
    auth = AuthorizationManifest("owned-log", "me", "self-owned", ("adapter_operation",))
    policy = ChameleonPolicy()
    decision = policy.evaluate(mode="live_packet_manipulation", authorization=auth)
    assert decision.decision == "FAIL"
