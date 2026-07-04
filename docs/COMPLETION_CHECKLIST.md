# Completion Checklist

- [x] Cargo workspace and crate blueprint created
- [x] Deterministic scheduler implemented
- [x] BCIK crossing implemented (`Closed` or typed residue)
- [x] 12-gate fail-closed vector implemented
- [x] Stitch tensor append + hash-chain verification implemented
- [x] Replay engine and deterministic harness implemented
- [x] Unit/property/integration/replay tests added
- [x] CI workflows for fmt/lint/build/test/proptest/replay/audit/no_std
- [x] Documentation and ADR set added
- [x] Desktop GUI roadmap added (planning only)

## Stage-2 Additions
- [x] Interop specification + compatibility matrix docs
- [x] `ssk-interop` reference implementation with strict decode guard and handshake checker
- [x] CLI hardening (`doctor`, `explain`, `--json`, error classes, next-step hints)
- [x] Versioned config schema + lint + migration baseline
- [x] Structured runtime observability + local metrics counters
- [x] Runbook + UX guidelines
- [x] Verification expansion (interop vectors/fuzz, CLI output checks, determinism regression)
- [x] CI guard extensions for interop/config compatibility

Deferred (P1/P2):
- [x] Signed capability attestation in interop handshake
- [x] Cross-implementation conformance suite
- [x] Extended incident automation and chaos recovery drills

## Stage-3 Additions (P1/P2 + Proxifier-replacement layer)
- [x] Signed capability attestation in interop handshake (`AttestationToken`, `SignedAttestation`, `Blake3KeyedVerifier`, `AttestationVerifier` trait)
- [x] Cross-implementation conformance suite (`ConformanceSuite`, 7 reference profiles, `ssk interop conformance` CLI command)
- [x] Incident/chaos recovery automation (`ssk-faultscan`: `FaultKind`, `inject_fault`, `run_drill`, `run_playbook`, `DrillReport`, `PlaybookReport`, `ssk chaos drill` CLI command)
- [x] `ssk-netadmin` crate — in-process Proxifier-replacement layer:
  - [x] Flow Intake (`FlowRecord`, `FlowDescriptor`, `ProtocolKind`, `RiskLevel`)
  - [x] Policy Engine (ordered rules, `allow`/`deny`/`redirect`/`split-route`/`require-attestation`/`fail-closed`)
  - [x] Route Orchestrator (Direct/SingleHop/MultiHop/Fallback/Denied, adapter registry)
  - [x] Identity & Attestation Binder (`AttestationBinder`, Blake3-keyed-hash MAC)
  - [x] Session Integrity (hash-chained `SessionLedger`, `SessionDecision`, `verify`)
  - [x] Control Plane (`OperatorProfile`, `TenantContext`, `RolloutMode`)
  - [x] Data Plane Adapters (`DirectAdapter`, `Socks5Adapter`, `HttpConnectAdapter`, `TlsTunnelAdapter`, `DnsOverrideAdapter`)
  - [x] Audit & Forensics (hash-chained `AuditLedger`, `ForensicEntry`, `verify`)
- [x] CLI: `ssk interop conformance`, `ssk chaos drill`, `ssk net-admin flow-inspect`, `ssk net-admin route-trace`, `ssk net-admin audit-dump`
- [x] `docs/NETADMIN_SPEC.md` specification
- [x] Architecture, checklist, and CI updated
