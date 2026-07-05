from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass(frozen=True)
class AuthorizationManifest:
    """Proof that traces/logs/endpoints are owned or explicitly authorized."""

    source_name: str
    owner_or_controller: str
    permission_basis: str
    allowed_uses: tuple[str, ...] = (
        "offline_analysis",
        "offline_redaction",
        "offline_reanalysis",
        "network_observation",
        "adapter_operation",
    )
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    evidence_ref: str | None = None

    def is_valid_for(self, use: str) -> bool:
        return bool(self.source_name and self.owner_or_controller and self.permission_basis and use in self.allowed_uses)


@dataclass(frozen=True)
class PolicyDecision:
    decision: str
    reason: str


@dataclass(frozen=True)
class ChameleonPolicy:
    """Runtime operation contract for kernel evaluations.

    The contract is intentionally small: it validates that an evaluation mode is
    supported and that the caller supplied an authorization manifest for the
    requested use. Unsupported mutation/evasion modes still fail explicitly, but
    normal uncertainty is handled by the gate bundle as an optimization signal.
    """

    require_authorization: bool = True
    allowed_modes: tuple[str, ...] = (
        "offline_analysis",
        "offline_redaction",
        "offline_reanalysis",
        "network_observation",
        "network_reanalysis",
        "adapter_operation",
    )
    blocked_modes: tuple[str, ...] = (
        "live_transform",
        "live_packet_manipulation",
        "proxy_or_vpn_control",
        "credential_use",
        "detector_bypass",
        "covert_channel",
        "packet_injection",
    )

    def evaluate(self, *, mode: str, authorization: AuthorizationManifest | None) -> PolicyDecision:
        if mode in self.blocked_modes:
            return PolicyDecision("FAIL", f"unsupported_operation:{mode}")
        if mode not in self.allowed_modes:
            return PolicyDecision("FAIL", f"mode_not_allowed:{mode}")
        if self.require_authorization:
            if authorization is None:
                return PolicyDecision("FAIL", "authorization_manifest_missing")
            if not authorization.is_valid_for(mode):
                return PolicyDecision("FAIL", f"authorization_manifest_invalid_for:{mode}")
        return PolicyDecision("PASS", "operation_contract_pass")
