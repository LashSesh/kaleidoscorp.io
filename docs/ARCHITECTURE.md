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
- `ssk-ipc`: request/response protocol between `ssk-cli` and `sskd`. Server **and** client on both transports — Unix domain socket and Windows named pipe; `DaemonClient::connect` dispatches on the `Endpoint` variant (`crates/ssk-ipc/src/client.rs:49-53`) and the Windows arm is a real `tokio::net::windows::named_pipe::NamedPipeClient` (`:34`). *Corrected 2026-08-11: this bullet previously said "server only … no named-pipe client exists in the tree". The client landed in P2, recorded DONE at `docs/WINDOWS_PRODUCT_ROADMAP.md:477`.*
- `ssk-daemon`: `sskd` — the real local system service: state machine, real `ssk-netcore`-backed activation, persisted hash-chained audit ledger

Decision-core data path: Intent -> Orbit -> Locator -> BCIK -> GateVector -> Tensor -> Focus -> Replay. This deterministic core (`ssk-runtime`) stays adapter-free and never touches a real network.

> **Corrected 2026-08-11.** The sentence above used to end "— that responsibility is layered below it, in `ssk-daemon`/`ssk-netcore`." There is no such layering. `ssk-runtime` and `ssk-netadmin` have no dependency relationship in either direction (`crates/ssk-runtime/Cargo.toml:7-24`, `crates/ssk-netadmin/Cargo.toml:15-23`), and `ssk-daemon` does not depend on `ssk-runtime` at all (`crates/ssk-daemon/Cargo.toml:11-47`). The decision core is a **parallel** path with its own entry point — `ssk-cli`'s `run` / `replay-verify` / `connect` subcommands (`crates/ssk-cli/src/main.rs:206`, `:214`, `:225`; dispatched at `:802`, `:808`, `:813`), each driving a hardcoded `sample_intent(valid_fixture)` (`:3967`, `:4031`, `:4101`). See `docs/adr/0008-flow-path-owns-the-per-connection-decision.md`.

The two paths, drawn side by side:

```
Path 1 — live per-connection decision        Path 2 — decision core
(the only path where a policy decision      (separate entry point, no sockets)
 reaches a real socket)

ssk-cli ──IPC──► sskd (ssk-daemon)           ssk-cli `run` | `replay-verify` | `connect`
                   │ FlowDescriptor                     │ sample_intent(valid_fixture)
                   ▼                                    ▼
             ssk-netadmin                          ssk-runtime
        PolicyEngine → RouteOrchestrator      Intent → Orbit → Locator → BCIK →
                   │ RouteCandidate           GateVector → Tensor → Focus → Replay
                   ▼                          (ssk-gates, ssk-bcik, ssk-imdf,
              ssk-netcore                      ssk-locator, ssk-focus, ssk-tensor)
        RouteExecutor → real socket
```

No edge crosses between the two columns, in either direction. They do share *foundation* crates —
`ssk-types`, `ssk-crypto` and `ssk-tensor` are on both (`crates/ssk-netadmin/Cargo.toml:16-18`) —
but no crate on either path calls into the other path's decision logic.

Observability path: Runtime event envelope (`run_id`, `replay_id`, `seeded`, `epoch`) + local metrics counters (`run_count`, `gate_failures`, `replay_drifts`).

## Network Administration Layer (`ssk-netadmin` + `ssk-netcore`)

`ssk-netadmin` plans; `ssk-netcore` executes. Together they sit between `sskd` and the
connections `sskd` itself opens, providing policy-driven egress:

> **Scope correction (2026-08-02).** This layer does **not** sit between local applications and the
> network, and it steers no third-party traffic. There is no ingress: no proxy listener, no
> WFP/WinDivert/LSP/TUN hook, no PAC, no proxy-settings writer. The only connections it sees are the
> ones `ssk activate --dest host:port` asks for, and no application bytes are written through them
> (`EgressSession::transport_mut`, `crates/ssk-netcore/src/session.rs:63`, has zero callers).
> Building ingress and dispatch is P4 of `docs/WINDOWS_PRODUCT_ROADMAP.md`.


> **Diagram correction (2026-08-11).** The diagram below used to begin `ssk-runtime → ssk-netadmin`.
> That edge has never existed. The real per-connection producer of the `FlowDescriptor` is `sskd`
> itself (`crates/ssk-daemon/src/supervisor.rs:544-552`), which then calls
> `PolicyEngine::evaluate` and `RouteOrchestrator::plan` (`:554-558`) and dispatches through
> `DataPlane::connect_route` (`:582`) over the real `NetcoreDataPlane`/`RouteExecutor` built at
> `crates/ssk-daemon/src/main.rs:272-273`.

```
ssk-cli  ──IPC──►  sskd  (ssk-daemon)
    │
    │  FlowDescriptor
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
