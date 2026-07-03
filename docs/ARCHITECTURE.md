# Architecture

The workspace follows the SSK Ω separation model:

- `ssk-types` / `ssk-core`: deterministic typed domain foundation
- `ssk-scheduler`: fixed-point deterministic phase ticks
- `ssk-bcik` + `ssk-gates`: fail-closed crossing and gate enforcement
- `ssk-tensor`: append-only hash-chained stitch persistence
- `ssk-replay`: deterministic replay diff verdicts
- `ssk-interop`: version/capability negotiation + strict canonical decode guards + signed attestation
- `ssk-config`: versioned fail-closed policy/config schema + migration baseline
- `ssk-runtime`: run orchestration and deterministic observability events
- `ssk-cli`: operator UX (`doctor`, `explain`, `--json`, config tooling, netadmin/chaos/interop commands)
- `ssk-faultscan`: chaos fault injection, recovery drills, and playbook automation
- `ssk-netadmin`: in-process network administration layer (Proxifier replacement)

Data path: Intent -> Orbit -> Locator -> BCIK -> GateVector -> Tensor -> Focus -> Replay.

Observability path: Runtime event envelope (`run_id`, `replay_id`, `seeded`, `epoch`) + local metrics counters (`run_count`, `gate_failures`, `replay_drifts`).

## Network Administration Layer (`ssk-netadmin`)

`ssk-netadmin` sits between `ssk-runtime` and all external connections. It provides
policy-driven traffic steering without any third-party proxy software:

```
ssk-runtime
    │
    ▼
┌─────────────────────────────────────────────────────┐
│                    ssk-netadmin                     │
│                                                     │
│  Flow Intake ──► Policy Engine ──► Route Orchestr. │
│       │               │                  │          │
│       ▼               ▼                  ▼          │
│  Attestation      Session Ledger    Data Plane      │
│  Binder           (hash-chain)      Adapters        │
│       │                                  │          │
│       └──────── Audit Ledger ◄───────────┘          │
│                  (hash-chain)                        │
│                                                     │
│  Control Plane: OperatorProfile / TenantContext     │
└─────────────────────────────────────────────────────┘
    │               │              │
    ▼               ▼              ▼
 Direct          SOCKS5      HTTP CONNECT / TLS
```

Key properties:
- **Fail-closed**: no matching rule → `FailClosed` action, connection is rejected
- **Attestation-gated**: `RequireAttestation` policy action blocks until peer MAC is verified
- **Deterministic audit**: every decision is hash-chained into an immutable `AuditLedger`
- **Replay-capable**: `SessionLedger` records all decisions with their hash chain for forensics
- **CLI-operable**: `ssk net-admin flow-inspect / route-trace / audit-dump`
