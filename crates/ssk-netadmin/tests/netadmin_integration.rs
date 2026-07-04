/// End-to-end integration test for the ssk-netadmin layer.
///
/// Exercises the complete pipeline:
///   FlowRecord → PolicyEngine → RouteOrchestrator → AttestationBinder →
///   SessionLedger → AuditLedger
use ssk_netadmin::{
    adapter::{DataPlaneAdapter, DirectAdapter, Socks5Adapter},
    attestation::{AttestationBinder, RawAttestation},
    audit::{AuditLedger, AuditOutcome},
    control::{ControlPlane, OperatorProfile, RolloutMode, TenantContext},
    flow::{FlowDescriptor, FlowRecord, ProtocolKind, RiskLevel},
    policy::{MatchCriteria, PolicyAction, PolicyEngine, PolicyRule},
    route::{AdapterRegistryEntry, HopSpec, RouteKind, RouteOrchestrator},
    session::SessionLedger,
};

fn build_engine() -> PolicyEngine {
    PolicyEngine::new(vec![
        PolicyRule {
            rule_id: "allow-internal".into(),
            description: "allow internal low-risk traffic directly".into(),
            priority: 10,
            criteria: MatchCriteria {
                app_prefix: None,
                dest_suffix: Some(".internal".into()),
                protocol: None,
                min_risk: None,
                max_risk: Some(RiskLevel::Low),
            },
            action: PolicyAction::Allow,
        },
        PolicyRule {
            rule_id: "proxy-high".into(),
            description: "route high-risk via socks5".into(),
            priority: 20,
            criteria: MatchCriteria {
                app_prefix: None,
                dest_suffix: None,
                protocol: None,
                min_risk: Some(RiskLevel::High),
                max_risk: None,
            },
            action: PolicyAction::Redirect {
                adapter_id: "socks5-exit".into(),
            },
        },
        PolicyRule {
            rule_id: "deny-critical-dns".into(),
            description: "deny critical DNS flows".into(),
            priority: 5,
            criteria: MatchCriteria {
                app_prefix: None,
                dest_suffix: None,
                protocol: Some(ProtocolKind::Dns),
                min_risk: Some(RiskLevel::Critical),
                max_risk: None,
            },
            action: PolicyAction::Deny,
        },
        PolicyRule {
            rule_id: "attest-before-tls".into(),
            description: "require attestation for TLS flows".into(),
            priority: 15,
            criteria: MatchCriteria {
                app_prefix: None,
                dest_suffix: None,
                protocol: Some(ProtocolKind::Tls),
                min_risk: Some(RiskLevel::Medium),
                max_risk: None,
            },
            action: PolicyAction::RequireAttestation {
                then: Box::new(PolicyAction::Redirect {
                    adapter_id: "socks5-exit".into(),
                }),
            },
        },
    ])
}

fn build_orchestrator() -> RouteOrchestrator {
    RouteOrchestrator::new(vec![AdapterRegistryEntry {
        adapter_id: "socks5-exit".into(),
        default_hop: HopSpec::new("socks5-exit", "proxy.corp.com", 1080),
    }])
}

fn build_control_plane() -> ControlPlane {
    let mut cp = ControlPlane::new(RolloutMode::Strict);
    cp.register_profile(OperatorProfile {
        profile_id: "standard".into(),
        name: "Standard".into(),
        allowed_adapters: vec!["direct".into(), "socks5-exit".into()],
        max_risk_level: RiskLevel::Critical,
        require_attestation: false,
    });
    cp.register_tenant(TenantContext {
        tenant_id: "t1".into(),
        profile_id: "standard".into(),
        isolation_tag: "zone-1".into(),
    });
    cp
}

#[test]
fn full_pipeline_allow_internal() {
    let engine = build_engine();
    let orc = build_orchestrator();
    let mut session = SessionLedger::new();
    let mut audit = AuditLedger::new();

    let flow = FlowRecord::new(
        "f-internal-001",
        1,
        FlowDescriptor::new(
            "app-internal",
            "db.internal",
            5432,
            ProtocolKind::Tcp,
            RiskLevel::Low,
        ),
    );

    let decision = engine.evaluate(&flow).expect("policy must eval");
    assert_eq!(decision.action, PolicyAction::Allow);

    let candidate = orc.plan(&flow, &decision).expect("route must plan");
    assert_eq!(candidate.route, RouteKind::Direct);

    let sd = session
        .record("sd-1", &flow.flow_id, decision.clone(), candidate.clone(), None)
        .expect("session record");
    assert_eq!(sd.flow_id, "f-internal-001");

    audit
        .record(
            "ae-1",
            &flow.flow_id,
            Some(sd.decision_id.clone()),
            None,
            &candidate.route,
            AuditOutcome::Dispatched,
            flow.intake_epoch,
        )
        .expect("audit record");

    session.verify().expect("session chain valid");
    audit.verify().expect("audit chain valid");
}

#[test]
fn full_pipeline_redirect_via_socks5() {
    let engine = build_engine();
    let orc = build_orchestrator();
    let mut session = SessionLedger::new();
    let mut audit = AuditLedger::new();

    let flow = FlowRecord::new(
        "f-high-001",
        2,
        FlowDescriptor::new(
            "app-external",
            "risky.example.com",
            443,
            ProtocolKind::Https,
            RiskLevel::High,
        ),
    );

    let decision = engine.evaluate(&flow).expect("policy eval");
    let candidate = orc.plan(&flow, &decision).expect("route plan");
    assert!(matches!(candidate.route, RouteKind::SingleHop(_)));

    let sd = session
        .record("sd-2", &flow.flow_id, decision.clone(), candidate.clone(), None)
        .expect("session record");

    audit
        .record(
            "ae-2",
            &flow.flow_id,
            Some(sd.decision_id.clone()),
            Some("socks5-exit".into()),
            &candidate.route,
            AuditOutcome::Dispatched,
            flow.intake_epoch,
        )
        .expect("audit record");

    session.verify().expect("session chain valid");
    audit.verify().expect("audit chain valid");
}

#[test]
fn full_pipeline_attestation_required_and_verified() {
    let engine = build_engine();
    let orc = build_orchestrator();
    let binder = AttestationBinder::new([0u8; 32]);
    let mut session = SessionLedger::new();
    let mut audit = AuditLedger::new();

    let flow = FlowRecord::new(
        "f-tls-001",
        3,
        FlowDescriptor::new(
            "app-secure",
            "secure.partner.com",
            8443,
            ProtocolKind::Tls,
            RiskLevel::Medium,
        ),
    );

    let decision = engine.evaluate(&flow).expect("policy eval");
    let candidate = orc.plan(&flow, &decision).expect("route plan");
    assert!(candidate.requires_attestation, "TLS flow must require attestation");

    // Build and sign a valid attestation.
    let mut raw = RawAttestation {
        subject_id: "peer-secure".into(),
        capabilities: vec!["gate-vector-12".into(), "replay-v1".into()],
        token_epoch: 3,
        nonce: 77,
        signature_hex: String::new(),
    };
    raw.signature_hex = binder.sign(&raw).expect("sign");
    let binding = binder.bind(&flow, &raw, 3).expect("attestation bind");

    let sd = session
        .record(
            "sd-3",
            &flow.flow_id,
            decision.clone(),
            candidate.clone(),
            Some(binding),
        )
        .expect("session record");
    assert!(sd.attestation.is_some());

    audit
        .record(
            "ae-3",
            &flow.flow_id,
            Some(sd.decision_id.clone()),
            Some("socks5-exit".into()),
            &candidate.route,
            AuditOutcome::Dispatched,
            flow.intake_epoch,
        )
        .expect("audit record");

    session.verify().expect("session chain valid");
    audit.verify().expect("audit chain valid");
}

#[test]
fn full_pipeline_fail_closed_no_match() {
    let engine = PolicyEngine::new(vec![]);
    let orc = RouteOrchestrator::default();
    let mut audit = AuditLedger::new();

    let flow = FlowRecord::new(
        "f-unknown-001",
        4,
        FlowDescriptor::new("unknown-app", "unknown.host", 9999, ProtocolKind::Tcp, RiskLevel::High),
    );

    let decision = engine.evaluate(&flow).expect("policy eval");
    let candidate = orc.plan(&flow, &decision).expect("route plan");
    assert!(candidate.is_denied());

    audit
        .record(
            "ae-fc",
            &flow.flow_id,
            None,
            None,
            &candidate.route,
            AuditOutcome::FailClosed,
            flow.intake_epoch,
        )
        .expect("audit record");

    audit.verify().expect("audit chain valid");
}

#[test]
fn control_plane_profile_adapter_check() {
    let cp = build_control_plane();
    assert!(cp.check_adapter("t1", "socks5-exit").is_ok());
    assert!(cp.check_adapter("t1", "unknown-proxy").is_err());
    assert!(cp.check_risk("t1", RiskLevel::Critical).is_ok());
    assert!(cp.check_risk("t1", RiskLevel::Low).is_ok());
}

#[test]
fn adapter_descriptors_are_coherent() {
    let direct = DirectAdapter::new("direct-default");
    let socks5 = Socks5Adapter::new("socks5-exit", "proxy.corp.com", 1080);

    let dd = direct.describe();
    let sd = socks5.describe();

    assert_eq!(dd.adapter_id, "direct-default");
    assert_eq!(sd.adapter_id, "socks5-exit");
    assert_eq!(sd.port, 1080);
}

#[test]
fn audit_chain_integrity_multi_entry() {
    let mut ledger = AuditLedger::new();
    for i in 0..10u32 {
        ledger
            .record(
                format!("e-{i}"),
                format!("f-{i}"),
                Some(format!("sd-{i}")),
                None,
                &RouteKind::Direct,
                AuditOutcome::Dispatched,
                u64::from(i),
            )
            .expect("record");
    }
    ledger.verify().expect("chain must be intact after 10 entries");
}
