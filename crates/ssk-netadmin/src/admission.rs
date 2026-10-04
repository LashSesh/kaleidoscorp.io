//! The in-process policy-to-transport boundary. This is not a cryptographic
//! capability and must never be reconstructed from client-supplied policy decisions.
use crate::{
    FlowRecord, NetAdminError, PolicyDecision, ProtocolKind, RouteKind, RouteOrchestrator,
};

/// An owned, single-use admission for one route and destination. The data plane
/// consumes it, so neither destination substitution nor accidental replay is
/// possible through that API. Deliberately not Clone or Deserialize.
///
/// ```compile_fail
/// use ssk_netadmin::admission::AdmissionToken;
/// let token = AdmissionToken { route: todo!(), host: String::new(), port: 443 };
/// ```
#[derive(Debug)]
pub struct AdmissionToken {
    route: RouteKind,
    host: String,
    port: u16,
}

impl AdmissionToken {
    #[must_use]
    pub fn route(&self) -> &RouteKind {
        &self.route
    }

    #[must_use]
    pub fn target(&self) -> (&str, u16) {
        (&self.host, self.port)
    }
}

impl RouteOrchestrator {
    /// Admit the trusted policy engine's decision for this flow. Required
    /// attestations remain denied until a flow-bound verifier is integrated;
    /// a deserialized AttestationBinding is not proof of verification.
    pub fn admit(
        &self,
        flow: &FlowRecord,
        decision: &PolicyDecision,
    ) -> Result<AdmissionToken, NetAdminError> {
        if flow.flow_id != decision.flow_id {
            return Err(NetAdminError::FailClosed(flow.flow_id.clone()));
        }
        let candidate = self.plan(flow, decision)?;
        if candidate.is_denied() {
            return Err(NetAdminError::FailClosed(flow.flow_id.clone()));
        }
        if candidate.requires_attestation {
            return Err(NetAdminError::AttestationRequired(flow.flow_id.clone()));
        }
        let d = &flow.descriptor;
        if d.destination_host.is_empty()
            || d.destination_host
                .chars()
                .any(|c| c.is_whitespace() || c.is_control())
            || d.destination_port == 0
            || matches!(
                d.protocol,
                ProtocolKind::Udp | ProtocolKind::Dns | ProtocolKind::Custom
            )
        {
            return Err(NetAdminError::NoViableRoute(flow.flow_id.clone()));
        }
        Ok(AdmissionToken {
            route: candidate.route,
            host: d.destination_host.clone(),
            port: d.destination_port,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FlowDescriptor, PolicyAction, RiskLevel};

    #[test]
    fn admission_rejects_missing_attestation_mismatched_flow_denial_and_udp() {
        let mut flow = FlowRecord::new(
            "flow",
            0,
            FlowDescriptor::new("app", "127.0.0.1", 443, ProtocolKind::Tcp, RiskLevel::Low),
        );
        let mut decision = PolicyDecision {
            flow_id: flow.flow_id.clone(),
            matched_rule: None,
            action: PolicyAction::Allow,
            rationale: String::new(),
        };
        let planner = RouteOrchestrator::default();
        let token = planner.admit(&flow, &decision).unwrap();
        assert_eq!(token.target(), ("127.0.0.1", 443));
        decision.action = PolicyAction::RequireAttestation {
            then: Box::new(PolicyAction::Allow),
        };
        assert!(matches!(
            planner.admit(&flow, &decision),
            Err(NetAdminError::AttestationRequired(_))
        ));
        decision.action = PolicyAction::Deny;
        assert!(planner.admit(&flow, &decision).is_err());
        decision.action = PolicyAction::Allow;
        decision.flow_id = "another-flow".into();
        assert!(planner.admit(&flow, &decision).is_err());
        decision.flow_id = flow.flow_id.clone();
        flow.descriptor.protocol = ProtocolKind::Udp;
        assert!(planner.admit(&flow, &decision).is_err());
    }
}
