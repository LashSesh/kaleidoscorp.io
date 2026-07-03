# ssk-netadmin — Network Administration Layer Specification

## Purpose

`ssk-netadmin` is the in-process network administration layer for the SSK Ω runtime.
It replaces the need for third-party proxy/routing software (Proxifier and equivalents)
by providing a cryptographically-secured, policy-driven traffic-steering subsystem
that operators control entirely through the SSK CLI and configuration system.

---

## Positioning

```
ssk-runtime  (produces outbound connection intents)
      │
      ▼
ssk-netadmin  (intercepts, classifies, enforces policy, routes)
      │
      ├─► Direct TCP/IP
      ├─► SOCKS5 proxy
      ├─► HTTP CONNECT tunnel
      ├─► TLS tunnel
      └─► DNS override / split-horizon
```

Integration bindings:
- `ssk-interop`: attestation MAC verification for peer identity
- `ssk-config`: policy profile loading and validation
- `ssk-cli`: `net-admin` command group
- Runtime observability: all decisions emit structured events

---

## Module Map

| Module | Responsibility |
|--------|---------------|
| `flow` | Classify outbound connection intents (app, destination, protocol, risk) |
| `policy` | Ordered rule evaluation → `allow / deny / redirect / split-route / require-attestation / fail-closed` |
| `route` | Multi-hop route planning, fallback chains, adapter selection |
| `attestation` | Blake3-keyed-hash MAC binding for peer/capability identity |
| `session` | Hash-chained decision ledger for forensic replay |
| `control` | Operator profiles, tenant contexts, rollout modes |
| `adapter` | Pluggable data-plane adapters (Direct / SOCKS5 / HTTP CONNECT / TLS / DNS) |
| `audit` | Immutable hash-chained forensic entries for all traffic decisions |

---

## Flow Intake

Every outbound connection intent produces a `FlowDescriptor`:

```
FlowDescriptor {
    app_id:      String,          // originating application context
    destination: String,          // host:port
    protocol:    ProtocolKind,    // Tcp | Udp | Tls | Http | Https | Custom
    risk:        RiskLevel,       // Low | Medium | High | Critical
}
```

The `FlowRecord` wraps the descriptor with a unique `flow_id` (UUID) and
`timestamp_ms` for audit correlation.

---

## Policy Engine

Rules are evaluated in insertion order. The first matching rule wins.
If no rule matches, the engine implicitly returns `FailClosed` — no traffic escapes by default.

### Match Criteria

Each rule may specify any combination of:
- `app_id` (exact string match)
- `destination_prefix` (string prefix of `host:port`)
- `protocol` (exact `ProtocolKind`)
- `max_risk` (risk levels at or below this threshold pass)

### Policy Actions

| Action | Effect |
|--------|--------|
| `Allow` | Pass through to route orchestration |
| `Deny` | Reject immediately, log decision |
| `Redirect(target)` | Rewrite destination to `target` |
| `SplitRoute(targets)` | Fan out to multiple targets |
| `RequireAttestation` | Block until attestation MAC is verified |
| `FailClosed` | Hard reject; used as default when no rule matches |

### API

```rust
let decision = engine.evaluate(&flow)?;
```

`PolicyDecision` carries the matched rule index and resolved `PolicyAction`.

---

## Route Orchestrator

Given a `PolicyDecision`, the orchestrator resolves a concrete `RouteCandidate`:

| Route Kind | Description |
|------------|-------------|
| `Direct` | Connect directly to destination |
| `SingleHop(HopSpec)` | Route through one proxy hop |
| `MultiHop(Vec<HopSpec>)` | Chained hops (onion-style) |
| `Fallback(primary, secondary)` | Try primary; fall back on error |
| `Denied` | No valid route; fail-closed |

`HopSpec` carries the proxy address, `AdapterKind`, and optional TLS/auth metadata.

Adapters are registered by `AdapterKind` key in the orchestrator registry;
unknown adapter kinds default to `Denied`.

---

## Identity & Attestation Binder

`AttestationBinder` signs flow descriptors with a Blake3 keyed-hash MAC using a
32-byte operator key:

```
mac = blake3::keyed_hash(key, cbor(flow_descriptor))
```

The resulting `AttestationBinding` carries the `flow_id`, `peer_id`, and `mac` bytes.
Verification is constant-time (byte equality on the recomputed MAC).

This binding integrates with `ssk-interop`'s `AttestationVerifier` trait for
cross-implementation attestation checks during the interop handshake.

---

## Session Integrity

`SessionLedger` records every decision in a hash chain:

```
entry_hash = blake3(prev_hash || serde_json(SessionDecision))
```

Each `SessionDecision` carries:
- `flow_id` and `session_id`
- `route_kind` (serialized as string)
- `policy_action` (serialized as string)
- `timestamp_ms`
- `prev_hash` and `entry_hash`

`SessionLedger::verify()` replays the chain and rejects any gap or mutation,
enabling deterministic forensic replay of all decisions.

---

## Control Plane

`ControlPlane` manages multiple `TenantContext` entries keyed by tenant ID.
Each tenant has an `OperatorProfile` and a `RolloutMode`:

| Rollout Mode | Behaviour |
|--------------|-----------|
| `Stable` | Full enforcement; all rules active |
| `Canary(percentage)` | Partial rollout; `percentage` of flows use new config |
| `Shadow` | Policy evaluated but decisions not enforced (observe-only) |
| `Maintenance` | Fail-closed for all flows in the tenant |

---

## Data Plane Adapters

All adapters implement the `DataPlaneAdapter` trait:

```rust
pub trait DataPlaneAdapter: Send + Sync {
    fn kind(&self) -> AdapterKind;
    fn describe(&self) -> AdapterDescriptor;
    fn connect(&self, destination: &str) -> Result<String, NetAdminError>;
}
```

| Adapter | Protocol |
|---------|---------|
| `DirectAdapter` | Raw TCP (no proxy) |
| `Socks5Adapter` | SOCKS5 via configured proxy host:port |
| `HttpConnectAdapter` | HTTP CONNECT tunnel via configured proxy host:port |
| `TlsTunnelAdapter` | TLS-wrapped tunnel with SNI override |
| `DnsOverrideAdapter` | Resolve destination via configured DNS override address |

---

## Audit & Forensics

`AuditLedger` maintains an immutable, append-only log of `ForensicEntry` records:

```
entry_hash = blake3(prev_hash || serde_json(ForensicEntry - entry_hash field))
```

Each entry records:
- `flow_id`, `session_id`, `app_id`, `destination`
- `outcome` (`Allowed | Denied | Redirected | AttestationFailed | FailClosed`)
- `route_kind`, `adapter_kind`, `timestamp_ms`
- `prev_hash` and `entry_hash`

`AuditLedger::verify()` validates the full chain; any insertion, deletion, or
mutation breaks the chain and is immediately detectable.

Operators dump the audit ledger via:

```
ssk net-admin audit-dump [--session <id>] [--since <timestamp>]
```

---

## Security Gates (Hard Requirements)

| Gate | Enforcement |
|------|------------|
| **Fail-closed default** | No matching rule → `FailClosed`; no bypass path |
| **Attestation-before-route** | `RequireAttestation` blocks route resolution until MAC verified |
| **Hash-chain integrity** | Both `SessionLedger` and `AuditLedger` verify on every `verify()` call |
| **Deny-on-unknown-adapter** | Unregistered `AdapterKind` → `Denied` route, never `Direct` fallback |
| **Signed policy changes** | Critical policy changes must be signed (enforced at config layer) |
| **Chaos drill integration** | Recovery playbooks in `ssk-faultscan` cover netadmin fault scenarios |

---

## Acceptance Criteria for "Proxifier Replacement Maturity"

1. **Policy-driven routing without third-party software** — all adapter types functional, CLI-operable
2. **Demonstrable interop/conformance** — `ssk interop conformance` passes all 7 reference profiles
3. **Reproducible incident recovery under fault** — `ssk chaos drill` passes without data-plane bypass
4. **Full CLI and telemetry operability** — `flow-inspect`, `route-trace`, `audit-dump` produce correct output
5. **Hash-chain forensics** — `SessionLedger::verify()` and `AuditLedger::verify()` detect any tampering

---

## CLI Commands

```
ssk net-admin flow-inspect <destination> [--app <id>] [--protocol <proto>] [--risk <level>]
    → Classify a flow and show policy decision + resolved route

ssk net-admin route-trace <destination> [--app <id>]
    → Show full route plan including hop specs and adapter kinds

ssk net-admin audit-dump [--session <id>] [--since <timestamp_ms>]
    → Dump forensic audit ledger entries; optionally verify hash chain
```
