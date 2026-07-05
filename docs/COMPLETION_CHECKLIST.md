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
  - [x] Data Plane Adapters (`DirectAdapter`, `Socks5Adapter`, `HttpConnectAdapter`, `TlsTunnelAdapter`, `DnsOverrideAdapter`) — **descriptor types only** at this stage; real transport landed in Stage 4 (`ssk-netcore`) below
  - [x] Audit & Forensics (hash-chained `AuditLedger`, `ForensicEntry`, `verify`)
- [x] CLI: `ssk interop conformance`, `ssk chaos drill`, `ssk net-admin flow-inspect`, `ssk net-admin route-trace`, `ssk net-admin audit-dump`
- [x] `docs/NETADMIN_SPEC.md` specification
- [x] Architecture, checklist, and CI updated

## Stage-4 Additions (real data-plane execution — closes SSKΩ-7)
- [x] `ssk-netcore` crate: real `RouteExecutor` dispatching `ssk-netadmin`'s planned `RouteKind` to an actual transport
  - [x] Direct: real `TcpStream::connect`
  - [x] SOCKS5: real RFC 1928 handshake + RFC 1929 username/password auth
  - [x] HTTP CONNECT: real request/response handshake, fails closed on non-2xx
  - [x] TLS tunnel: real `rustls` handshake (`ring` provider) against the OS-native trust store; mTLS client-cert plumbing exists but has no config source yet
  - [x] DNS override: real UDP query with TCP fallback on truncation, RFC 1035 name (de)compression
  - [x] Multi-hop chaining (Direct/SOCKS5/HTTP-CONNECT/TLS composed per hop)
  - [x] Real health probing (`RouteExecutor::probe`, real connect-and-teardown, typed `ProbeReport`)
- [x] `ssk-daemon`: `MockDataPlane` removed from the production binary; `activate_profile` requires a real `dest_host`/`dest_port` and only reports `Protected` after a real `ssk-netcore` connect succeeds; `Deactivate` really tears the session down; `dns_protected`/adapter health derived from the real session, never hardcoded
- [x] `ssk-daemon`: audit ledger is no longer vacuous — real activate/route decisions are recorded and hash-chain-verified
- [x] `ssk-cli`: `ssk activate --profile <p> --dest <host:port>` is a real, user-reachable command driving the above end-to-end
- [x] Real system tests: `ssk-netcore` unit tests against real local listeners/wire-protocol-compliant fake servers; `ssk-daemon`'s `round_trip.rs` spawns the real `sskd` binary and drives it to really connect; `ssk-cli`'s `activate_real_egress.rs` spawns real `ssk`+`sskd` binaries end-to-end
- [x] `cargo deny check` fixed to genuinely pass (`bans`): every internal path dependency now carries an explicit `version`, closing a previously-undiscovered wildcard-dependency failure across all 23 crates
- [x] `ssk-core` `no_std` build fixed (missing `alloc::vec::Vec` import) — the advertised `no_std_core` CI job now genuinely passes

**Explicitly not yet built** (do not read the above as "the whole product is done"):
- `ssk-capture` — automatic classification/capture of arbitrary local application traffic. This is a separate, higher-privilege layer (OS-level interception) than adapter-level egress and was deliberately not started without explicit user sign-off on its blast radius.
- A desktop GUI.
- OS-level service integration (systemd/launchd units, install packaging that ships binaries rather than source).
- A system-wide kill switch enforced at the network-stack level (today's mechanism tears down the one session `sskd` holds — real, but not system-wide).
- A config-driven, multi-profile model (the daemon still uses one hardcoded reference policy/route configuration; Phase 5 work).
- Full multi-hop proxy chaining is implemented but only lightly exercised (single-hop SOCKS5/HTTP-CONNECT/TLS are the tested, product-relevant cases today).
