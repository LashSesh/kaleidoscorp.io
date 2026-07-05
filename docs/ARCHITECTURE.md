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
- `ssk-netadmin`: in-process network administration layer — real, policy-driven route **planning** (adapter-free, `no_std`-friendly)
- `ssk-netcore`: real route **execution** — Direct/SOCKS5/HTTP-CONNECT/TLS egress, DNS-override resolution, health probing (closes SSKΩ-7)
- `ssk-ipc`: request/response protocol (Unix socket; Windows named-pipe path written but unverified in CI) between `ssk-cli` and `sskd`
- `ssk-daemon`: `sskd` — the real local system service: state machine, real `ssk-netcore`-backed activation, persisted hash-chained audit ledger

Data path: Intent -> Orbit -> Locator -> BCIK -> GateVector -> Tensor -> Focus -> Replay. This deterministic core (`ssk-runtime`) stays adapter-free and never touches a real network — that responsibility is layered below it, in `ssk-daemon`/`ssk-netcore`.

Observability path: Runtime event envelope (`run_id`, `replay_id`, `seeded`, `epoch`) + local metrics counters (`run_count`, `gate_failures`, `replay_drifts`).

## Network Administration Layer (`ssk-netadmin` + `ssk-netcore`)

`ssk-netadmin` plans; `ssk-netcore` executes. Together they sit between `sskd` and all
external connections, providing policy-driven traffic steering without any third-party
proxy software:

```
ssk-runtime
    │
    ▼
┌─────────────────────────────────────────────────────┐
│              ssk-netadmin  (planning)               │
│                                                     │
│  Flow Intake ──► Policy Engine ──► Route Orchestr. │
│       │               │                  │          │
│       ▼               ▼                  ▼          │
│  Attestation      Session Ledger    RouteCandidate  │
│  Binder           (hash-chain)                       │
│       │                                              │
│       └──────── Audit Ledger ◄───────────            │
│                  (hash-chain)                        │
│                                                     │
│  Control Plane: OperatorProfile / TenantContext     │
└──────────────────────┬──────────────────────────────┘
                       │  RouteCandidate
                       ▼
┌─────────────────────────────────────────────────────┐
│               ssk-netcore  (execution)              │
│  RouteExecutor: real TCP / SOCKS5 / HTTP CONNECT /  │
│  TLS handshakes + real DNS query, chained per hop,  │
│  with real health probing (ProbeReport)             │
└──────────────────────┬──────────────────────────────┘
                       │  real socket
                       ▼
              the real destination
```

Key properties:
- **Fail-closed**: no matching rule → `FailClosed` action, connection is rejected; an unregistered/unsupported adapter fails closed rather than falling back to Direct
- **Attestation-gated**: `RequireAttestation` policy action blocks until peer MAC is verified (a symmetric BLAKE3 keyed-MAC today, not an asymmetric signature — see `docs/DESKTOP_CLIENT_ARCHITECTURE.md`)
- **Deterministic audit**: every decision is hash-chained into an immutable `AuditLedger`; `ssk-daemon` records real activate/route decisions into a disk-persisted ledger, so `verify-audit-chain` verifies real, non-empty history
- **Replay-capable**: `SessionLedger` records all decisions with their hash chain for forensics
- **CLI-operable**: `ssk net-admin flow-inspect / route-trace / audit-dump`, and `ssk activate --dest host:port` for real, policy-decided egress through `sskd`

**Not yet built**: `ssk-capture` (automatic classification of arbitrary local application traffic — a separate, higher-privilege layer than adapter-level egress); OS-level service integration (systemd/launchd units); a system-wide kill switch enforced at the network-stack level (today the daemon's kill-switch-adjacent mechanism tears down the one session it holds).
