//! Operation contract — Chameleon `policy`.
//!
//! [`ChameleonPolicy`] validates that an evaluation mode is supported and that
//! an [`AuthorizationManifest`] covers the requested use. The allowed/blocked
//! mode sets are **configurable fields with the kernel author's own defaults**
//! — this port keeps them parametric rather than hard-coding any of them, and
//! carries no clock (a manifest's `created_at` is caller-supplied) so evaluation
//! stays deterministic and replay-friendly.

/// Outcome of a policy evaluation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyOutcome {
    Pass,
    Fail,
}

impl PolicyOutcome {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            PolicyOutcome::Pass => "PASS",
            PolicyOutcome::Fail => "FAIL",
        }
    }

    #[must_use]
    pub fn is_pass(self) -> bool {
        matches!(self, PolicyOutcome::Pass)
    }
}

/// A policy decision: outcome + machine-readable reason.
#[derive(Clone, Debug, PartialEq)]
pub struct PolicyDecision {
    pub outcome: PolicyOutcome,
    pub reason: String,
}

impl PolicyDecision {
    fn pass() -> Self {
        PolicyDecision {
            outcome: PolicyOutcome::Pass,
            reason: "operation_contract_pass".to_owned(),
        }
    }

    fn fail(reason: impl Into<String>) -> Self {
        PolicyDecision {
            outcome: PolicyOutcome::Fail,
            reason: reason.into(),
        }
    }
}

fn default_allowed_uses() -> Vec<String> {
    [
        "offline_analysis",
        "offline_redaction",
        "offline_reanalysis",
        "network_observation",
        "adapter_operation",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

/// Proof that traces/logs/endpoints are owned or explicitly authorized.
#[derive(Clone, Debug, PartialEq)]
pub struct AuthorizationManifest {
    pub source_name: String,
    pub owner_or_controller: String,
    pub permission_basis: String,
    pub allowed_uses: Vec<String>,
    /// Caller-supplied timestamp (no implicit clock, for determinism).
    pub created_at: Option<String>,
    pub evidence_ref: Option<String>,
}

impl AuthorizationManifest {
    #[must_use]
    pub fn new(
        source_name: impl Into<String>,
        owner_or_controller: impl Into<String>,
        permission_basis: impl Into<String>,
    ) -> Self {
        AuthorizationManifest {
            source_name: source_name.into(),
            owner_or_controller: owner_or_controller.into(),
            permission_basis: permission_basis.into(),
            allowed_uses: default_allowed_uses(),
            created_at: None,
            evidence_ref: None,
        }
    }

    #[must_use]
    pub fn with_allowed_uses<I, S>(mut self, uses: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.allowed_uses = uses.into_iter().map(Into::into).collect();
        self
    }

    #[must_use]
    pub fn with_evidence_ref(mut self, evidence_ref: impl Into<String>) -> Self {
        self.evidence_ref = Some(evidence_ref.into());
        self
    }

    #[must_use]
    pub fn is_valid_for(&self, use_: &str) -> bool {
        !self.source_name.is_empty()
            && !self.owner_or_controller.is_empty()
            && !self.permission_basis.is_empty()
            && self.allowed_uses.iter().any(|u| u == use_)
    }
}

fn default_allowed_modes() -> Vec<String> {
    [
        "offline_analysis",
        "offline_redaction",
        "offline_reanalysis",
        "network_observation",
        "network_reanalysis",
        "adapter_operation",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn default_blocked_modes() -> Vec<String> {
    [
        "live_transform",
        "live_packet_manipulation",
        "proxy_or_vpn_control",
        "credential_use",
        "detector_bypass",
        "covert_channel",
        "packet_injection",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

/// The runtime operation contract (Chameleon `ChameleonPolicy`). All three sets
/// are configurable; the defaults reproduce the kernel author's own.
#[derive(Clone, Debug, PartialEq)]
pub struct ChameleonPolicy {
    pub require_authorization: bool,
    pub allowed_modes: Vec<String>,
    pub blocked_modes: Vec<String>,
}

impl Default for ChameleonPolicy {
    fn default() -> Self {
        ChameleonPolicy {
            require_authorization: true,
            allowed_modes: default_allowed_modes(),
            blocked_modes: default_blocked_modes(),
        }
    }
}

impl ChameleonPolicy {
    #[must_use]
    pub fn evaluate(
        &self,
        mode: &str,
        authorization: Option<&AuthorizationManifest>,
    ) -> PolicyDecision {
        if self.blocked_modes.iter().any(|m| m == mode) {
            return PolicyDecision::fail(format!("unsupported_operation:{mode}"));
        }
        if !self.allowed_modes.iter().any(|m| m == mode) {
            return PolicyDecision::fail(format!("mode_not_allowed:{mode}"));
        }
        if self.require_authorization {
            match authorization {
                None => return PolicyDecision::fail("authorization_manifest_missing"),
                Some(auth) if !auth.is_valid_for(mode) => {
                    return PolicyDecision::fail(format!(
                        "authorization_manifest_invalid_for:{mode}"
                    ));
                }
                Some(_) => {}
            }
        }
        PolicyDecision::pass()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_valid_for_offline_analysis() {
        let auth = AuthorizationManifest::new("owned-log", "me", "self-owned lab data")
            .with_allowed_uses(["offline_analysis"]);
        assert!(auth.is_valid_for("offline_analysis"));
        assert!(!auth.is_valid_for("network_observation"));
    }

    #[test]
    fn policy_requires_authorization() {
        let decision = ChameleonPolicy::default().evaluate("offline_analysis", None);
        assert_eq!(decision.outcome, PolicyOutcome::Fail);
        assert!(decision.reason.contains("authorization"));
    }

    #[test]
    fn policy_allows_authorized_network_observation() {
        let auth = AuthorizationManifest::new("owned-log", "me", "self-owned")
            .with_allowed_uses(["network_observation"]);
        let decision = ChameleonPolicy::default().evaluate("network_observation", Some(&auth));
        assert_eq!(decision.outcome, PolicyOutcome::Pass);
    }

    #[test]
    fn policy_denies_unsupported_live_mutation() {
        let auth = AuthorizationManifest::new("owned-log", "me", "self-owned")
            .with_allowed_uses(["adapter_operation"]);
        let decision = ChameleonPolicy::default().evaluate("live_packet_manipulation", Some(&auth));
        assert_eq!(decision.outcome, PolicyOutcome::Fail);
        assert!(decision.reason.starts_with("unsupported_operation"));
    }
}
