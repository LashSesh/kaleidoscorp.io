#![forbid(unsafe_code)]

//! Control Plane — operator profiles, tenant/context separation, rollout modes.

use serde::{Deserialize, Serialize};

use crate::error::NetAdminError;
use crate::flow::RiskLevel;

/// Rollout mode controls how aggressively the netadmin layer enforces policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum RolloutMode {
    /// Full enforcement: deny/redirect/attest as configured.
    #[default]
    Strict,
    /// Shadow mode: evaluate policy, log decisions, but do not enforce.
    /// Useful for pre-flight testing of new rules.
    Shadow,
    /// Audit mode: allow all flows but record every decision forensically.
    Audit,
    /// Emergency mode: allow all flows with full audit; must be time-limited.
    Emergency,
}

impl RolloutMode {
    /// Returns `true` when policy decisions should be enforced.
    #[must_use]
    pub fn is_enforcing(&self) -> bool {
        matches!(self, Self::Strict)
    }

    /// Returns `true` when decisions must always be logged.
    #[must_use]
    pub fn requires_full_audit(&self) -> bool {
        matches!(self, Self::Audit | Self::Emergency)
    }
}

/// Operator profile: a named set of constraints applied to flows within a
/// tenant context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorProfile {
    /// Unique profile identifier.
    pub profile_id: String,
    /// Human-readable display name.
    pub name: String,
    /// Adapter IDs the profile is allowed to use.
    pub allowed_adapters: Vec<String>,
    /// Maximum risk level the profile can route without additional controls.
    pub max_risk_level: RiskLevel,
    /// Whether flows require a signed attestation before dispatch.
    pub require_attestation: bool,
}

impl OperatorProfile {
    /// Returns `true` when the adapter is permitted under this profile.
    #[must_use]
    pub fn allows_adapter(&self, adapter_id: &str) -> bool {
        self.allowed_adapters.iter().any(|a| a == adapter_id)
    }

    /// Returns `true` when the risk level is within the profile's limit.
    #[must_use]
    pub fn allows_risk(&self, risk: RiskLevel) -> bool {
        risk <= self.max_risk_level
    }
}

/// Tenant context: associates a tenant with an operator profile and an
/// isolation tag (used to namespace forensic records).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantContext {
    pub tenant_id: String,
    pub profile_id: String,
    /// Arbitrary string used to isolate audit records by context.
    pub isolation_tag: String,
}

/// The control plane manages profiles, tenants, and rollout mode.
#[derive(Debug, Default)]
pub struct ControlPlane {
    profiles: Vec<OperatorProfile>,
    tenants: Vec<TenantContext>,
    pub rollout_mode: RolloutMode,
}

impl ControlPlane {
    #[must_use]
    pub fn new(rollout_mode: RolloutMode) -> Self {
        Self {
            profiles: Vec::new(),
            tenants: Vec::new(),
            rollout_mode,
        }
    }

    /// Register an operator profile.
    pub fn register_profile(&mut self, profile: OperatorProfile) {
        self.profiles.push(profile);
    }

    /// Register a tenant context.
    pub fn register_tenant(&mut self, tenant: TenantContext) {
        self.tenants.push(tenant);
    }

    /// Look up a tenant by id.
    pub fn tenant(&self, tenant_id: &str) -> Result<&TenantContext, NetAdminError> {
        self.tenants
            .iter()
            .find(|t| t.tenant_id == tenant_id)
            .ok_or_else(|| NetAdminError::UnknownTenant(tenant_id.into()))
    }

    /// Look up the profile for a tenant.
    pub fn profile_for_tenant(
        &self,
        tenant_id: &str,
    ) -> Result<&OperatorProfile, NetAdminError> {
        let tenant = self.tenant(tenant_id)?;
        self.profiles
            .iter()
            .find(|p| p.profile_id == tenant.profile_id)
            .ok_or_else(|| NetAdminError::UnknownTenant(tenant.profile_id.clone()))
    }

    /// Validate that an adapter is permitted for the tenant's profile.
    pub fn check_adapter(
        &self,
        tenant_id: &str,
        adapter_id: &str,
    ) -> Result<(), NetAdminError> {
        let profile = self.profile_for_tenant(tenant_id)?;
        if profile.allows_adapter(adapter_id) {
            Ok(())
        } else {
            Err(NetAdminError::UnknownAdapter(format!(
                "adapter `{adapter_id}` not permitted for tenant `{tenant_id}`"
            )))
        }
    }

    /// Validate that a risk level is acceptable for the tenant's profile.
    pub fn check_risk(
        &self,
        tenant_id: &str,
        risk: RiskLevel,
    ) -> Result<(), NetAdminError> {
        let profile = self.profile_for_tenant(tenant_id)?;
        if profile.allows_risk(risk) {
            Ok(())
        } else {
            Err(NetAdminError::FailClosed(format!(
                "risk level {risk:?} exceeds profile max for tenant `{tenant_id}`"
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_plane() -> ControlPlane {
        let mut plane = ControlPlane::new(RolloutMode::Strict);
        plane.register_profile(OperatorProfile {
            profile_id: "standard".into(),
            name: "Standard Operator".into(),
            allowed_adapters: vec!["direct".into(), "socks5-exit".into()],
            max_risk_level: RiskLevel::High,
            require_attestation: false,
        });
        plane.register_tenant(TenantContext {
            tenant_id: "tenant-a".into(),
            profile_id: "standard".into(),
            isolation_tag: "zone-a".into(),
        });
        plane
    }

    #[test]
    fn adapter_allowed() {
        let plane = default_plane();
        assert!(plane.check_adapter("tenant-a", "socks5-exit").is_ok());
    }

    #[test]
    fn unknown_adapter_rejected() {
        let plane = default_plane();
        assert!(plane.check_adapter("tenant-a", "ghost").is_err());
    }

    #[test]
    fn risk_within_limit_allowed() {
        let plane = default_plane();
        assert!(plane.check_risk("tenant-a", RiskLevel::High).is_ok());
    }

    #[test]
    fn critical_risk_exceeds_limit() {
        let plane = default_plane();
        assert!(plane.check_risk("tenant-a", RiskLevel::Critical).is_err());
    }

    #[test]
    fn unknown_tenant_error() {
        let plane = default_plane();
        assert!(plane.tenant("ghost-tenant").is_err());
    }

    #[test]
    fn shadow_mode_is_not_enforcing() {
        let plane = ControlPlane::new(RolloutMode::Shadow);
        assert!(!plane.rollout_mode.is_enforcing());
    }

    #[test]
    fn strict_mode_is_enforcing() {
        let plane = ControlPlane::new(RolloutMode::Strict);
        assert!(plane.rollout_mode.is_enforcing());
    }
}
