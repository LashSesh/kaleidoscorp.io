# ScorpioSync-Kaleidoscorp Ω

**Production-oriented, pure Rust runtime** implementing the ScorpioSync-Kaleidoscorp Ω master specification.

[![CI](https://github.com/LashSesh/kaleidoscorp.io/actions/workflows/ci.yml/badge.svg)](https://github.com/LashSesh/kaleidoscorp.io/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Crate Map](#crate-map)
4. [Security Posture](#security-posture)
5. [Quickstart](#quickstart)
6. [CLI Reference](#cli-reference)
7. [Configuration](#configuration)
8. [Interoperability](#interoperability)
9. [Network Administration Layer](#network-administration-layer)
10. [Development](#development)
11. [CI Matrix](#ci-matrix)
12. [Release](#release)
13. [Roadmap](#roadmap)
14. [Contributing](#contributing)
15. [Documentation](#documentation)

---

## Overview

ScorpioSync-Kaleidoscorp Ω (SSK Ω) is a deterministic, replay-verifiable runtime with fail-closed enforcement at every layer. It provides:

- **Deterministic execution** — every pipeline run is fully replayable via BLAKE3 hash-chained manifests.
- **Fail-closed gate vector** — a 12-gate enforcement system; any gate failure halts the pipeline immediately.
- **Canonical wire format** — strict CBOR encoding with BLAKE3 content-addressing (SHA-256 compatibility available).
- **Versioned interoperability** — explicit version/capability negotiation with strict decode guards.
- **Production-grade CLI** — structured JSON output, unified exit-code taxonomy, and self-diagnostic tooling.
- **In-process network administration** — policy-driven, cryptographically-audited (BLAKE3 hash-chained) traffic routing without third-party proxy software, with real Direct/SOCKS5/HTTP-CONNECT/TLS egress and DNS-override resolution (`ssk-netcore`) dispatched through the daemon (`sskd`).

> **Honest maturity note.** The decision/audit/planning core (Intent→Orbit→Locator→BCIK→GateVector→Tensor→Focus→Replay) is real, deterministic, and heavily tested. Real network egress now exists (`ssk-netcore`) and is reachable via `ssk activate --dest host:port`, which the daemon dispatches through the real policy engine to a real adapter and holds open for as long as the profile stays `Protected`. What is **not yet** built: automatic traffic capture/classification of arbitrary local flows (`ssk-capture`), a desktop GUI, OS-level service integration (systemd/launchd units), and a system-wide kill-switch that blocks traffic at the network-stack level. See [`docs/OMEGA_CORE_CONFORMANCE_SPEC.md`](docs/OMEGA_CORE_CONFORMANCE_SPEC.md) for the rung-by-rung conformance status.

---

## Architecture

Two distinct paths share this workspace, and the split is deliberate: the decision core stays deterministic and adapter-free; real network liveness lives only in the daemon/netcore layer below it.

```
Deterministic core (ssk-runtime, no network I/O, no adapters):
Intent → Orbit → Locator → BCIK → GateVector → Tensor → Focus → Replay
```

```
┌─────────────────────────────────────────────────┐
│                  ssk-runtime                    │
│  Orchestrates the full pipeline; emits          │
│  structured observability events per run        │
│  (run_id, replay_id, seeded, epoch)             │
└──────────────────────┬──────────────────────────┘
                       │
         ┌─────────────▼────────────┐
         │       ssk-netadmin       │  ← policy-driven route *planning*
         │  Flow Intake → Policy    │    (real, tested, adapter-free)
         │  Engine → Route Orchest. │
         │  Attestation → Audit     │
         └─────────────┬────────────┘
                       │  RouteCandidate
         ┌─────────────▼────────────┐
         │        ssk-netcore       │  ← policy-planned route *execution*
         │  RouteExecutor: real     │
         │  Direct / SOCKS5 / HTTP  │
         │  CONNECT / TLS / DNS     │
         │  + real health probing   │
         └─────────────┬────────────┘
                       │  real socket
                       ▼
              (the actual destination)
```

**User-reachable path**: `ssk activate --profile <p> --dest host:port` (`ssk-cli`) → real Unix-socket IPC → `sskd` (`ssk-daemon`) evaluates the real policy engine, plans a real route, and drives `ssk-netcore` to really connect. `Protected` is reported only after a real handshake succeeds; `FailClosed` is reported — with a real, typed reason — otherwise. `ssk deactivate` really tears the session down.

**Observability path**: every run emits a structured event envelope carrying `run_id`, `replay_id`, `seeded`, and `epoch`. Local metrics counters (`run_count`, `gate_failures`, `replay_drifts`) accumulate without external dependencies.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full diagram and module breakdown.

---

## Crate Map

| Crate | Role |
|-------|------|
| `ssk-types` | Deterministic typed domain primitives (`no_std`-compatible) |
| `ssk-core` | Domain logic foundation (`no_std`-compatible) |
| `ssk-scheduler` | Fixed-point deterministic phase scheduler |
| `ssk-identity` | Identity and session management |
| `ssk-locator` | Locator pool and trust classification |
| `ssk-bcik` | BCIK crossing enforcement |
| `ssk-gates` | Fail-closed 12-gate vector |
| `ssk-stitch` | Stitch management and persistence |
| `ssk-tensor` | Append-only hash-chained stitch tensor (memory + file-ledger backends) |
| `ssk-focus` | Focus and residue tracking |
| `ssk-audit` | Immutable audit ledger |
| `ssk-replay` | Deterministic replay diff verdicts |
| `ssk-faultscan` | Chaos fault injection, recovery drills, and playbook automation |
| `ssk-privacy` | Privacy policy enforcement |
| `ssk-crypto` | Cryptographic primitives (BLAKE3, SHA-256, keyed hash) |
| `ssk-config` | Versioned fail-closed policy/config schema + migration baseline |
| `ssk-interop` | Version/capability negotiation + strict canonical CBOR decode + signed attestation |
| `ssk-runtime` | Run orchestration and deterministic observability events |
| `ssk-sim` | Simulation harness |
| `ssk-netadmin` | In-process network administration layer: policy-driven route **planning** (adapter-free, no network I/O) |
| `ssk-netcore` | Real route **execution**: Direct/SOCKS5/HTTP-CONNECT/TLS egress, DNS-override resolution, health probing |
| `ssk-ipc` | Unix-socket (Windows named-pipe path unverified) request/response protocol between `ssk-cli` and `sskd` |
| `ssk-daemon` | `sskd` — the real local system service: state machine, policy-driven activation, real `ssk-netcore`-backed egress, persisted audit ledger |
| `ssk-cli` | Operator UX (`doctor`, `explain`, `--json`, config tooling, `activate`/`deactivate`/`status`, netadmin commands) |

> **`no_std` note**: `ssk-types` and `ssk-core` are `no_std`-friendly and verified in CI via `cargo check --no-default-features`.

---

## Security Posture

SSK Ω operates under an **Adamant-Grade** security baseline. Every layer defaults to deny, quarantine, and record — never silently allow.

| Principle | Implementation |
|-----------|---------------|
| **Fail-closed** | Gate vector, policy engine, and config all default to `fail_closed = true`. No rule match → deny. |
| **No unsafe code** | `#![forbid(unsafe_code)]` enforced workspace-wide. |
| **Deterministic execution** | All pipeline runs are replay-verifiable via hash-chained manifests. |
| **Immutable audit trail** | Session and forensic ledgers are BLAKE3 hash-chained; tampering is immediately detectable. |
| **Strict attestation** | Interop handshakes verify capability attestations before accepting peers. |
| **Least privilege** | Operator profiles constrain adapters and risk levels per tenant. |
| **Supply-chain hygiene** | GitHub Actions pinned to commit SHAs; `cargo audit` and `cargo deny` run in CI; Dependabot enabled. |
| **Clock skew enforcement** | Peers with `deterministic_clock_epoch` outside ±300 s are rejected at handshake. |

For vulnerability reporting, see [`SECURITY.md`](SECURITY.md).

---

## Quickstart

**Prerequisites**: [Rust stable toolchain](https://rustup.rs/).

```bash
# 1. Build everything
cargo build --workspace

# 2. Health-check the local environment
cargo run -p ssk-cli -- doctor

# 3. Execute a run
cargo run -p ssk-cli -- run --valid-fixture true

# 4. Verify deterministic replay
cargo run -p ssk-cli -- replay-verify --valid-fixture true

# 5. Verify ledger integrity
cargo run -p ssk-cli -- verify-ledger --path /tmp/ledger.json
```

All commands accept `--json` for machine-readable output suitable for automation and monitoring pipelines.

### Minimal runtime example

```rust
use ssk_gates::GateVector;
use ssk_locator::LocatorPool;
use ssk_runtime::{sample_intent, Runtime};
use ssk_tensor::MemoryBackend;
use ssk_types::{Locator, LocatorId, LocatorType};

fn main() {
    let tensor = MemoryBackend::new();
    let runtime = Runtime {
        gate_vector: GateVector::with_all_default(),
        tensor: &tensor,
    };
    let pool = LocatorPool::new(vec![Locator {
        id: LocatorId::new("local"),
        locator_type: LocatorType::LocalOverlay,
        trusted: true,
        risk_score: 10,
    }]);

    let (outcome, _) = runtime
        .run_once(sample_intent(true), &pool)
        .expect("runtime should run");
    println!("{:?}", outcome.gate_report.outcome);
}
```

See [`examples/mvr.rs`](examples/mvr.rs) for the full runnable example.

---

## CLI Reference

```
ssk [--json] <command>
```

| Command | Description |
|---------|-------------|
| `doctor` | Run health checks (environment, config, gates, entropy) |
| `run` | Execute a pipeline run |
| `replay-verify` | Verify deterministic replay consistency |
| `verify-ledger` | Verify the hash-chain integrity of a ledger file |
| `explain <topic>` | Print human + machine diagnostics for an error or gate |
| `config lint` | Validate a config file against the schema |
| `config schema` | Export the config schema as JSON |
| `net-admin flow-inspect` | Classify a flow and show policy decision + resolved route |
| `net-admin route-trace` | Show full route plan including hop specs and adapter kinds |
| `net-admin audit-dump` | Dump the forensic audit ledger; optionally verify hash chain |
| `status` | Query the real daemon (`sskd`) state over its Unix-socket IPC |
| `activate --profile <p> --dest <host:port>` | Ask `sskd` to really connect to `host:port` via the policy-decided route; `Protected` only on real success |
| `deactivate` | Really tear down the live egress session and return to `Inactive` |
| `list-profiles` | List profiles known to the daemon (currently one reference profile; a config-driven multi-profile model is future work) |

Every error output includes a machine code, error class, exit code, and actionable next steps. Use `ssk explain <error>` for extended diagnostics.

`status`/`activate`/`deactivate`/`list-profiles` require `sskd` to be running (`cargo run -p ssk-daemon --bin sskd`); they exit with a clear `IPC_CONNECT_FAILED`-class error otherwise, never a silent success.

---

## Configuration

SSK Ω uses a versioned, fail-closed config model. The minimum valid configuration requires:

```yaml
version: 2
fail_closed: true
runtime:
  strict_mode: true
```

```bash
# Validate a config file
cargo run -p ssk-cli -- config lint --path ./ssk-config.yaml

# Export the full JSON schema
cargo run -p ssk-cli -- config schema --json
```

Legacy v1 configs are automatically migrated on first load. Restart is blocked unless `config lint` succeeds.

---

## Interoperability

SSK Ω uses a canonical CBOR wire format with explicit version and capability negotiation.

### Protocol version: `1.0.0`

| Local | Peer | Result |
|-------|------|--------|
| 1.0.0 | 1.0.0 / 1.0.x / 1.1.x | ✅ Compatible |
| 1.0.0 | 0.x.y or 2.x.y | ❌ Major mismatch — rejected |

### Required capabilities

Both peers must advertise `gate-vector-12` and `replay-v1`. Missing any required capability produces `CapabilityMismatch`.

### Decoder modes

| Mode | Behavior |
|------|----------|
| `Strict` (default) | Canonical byte equality required; non-canonical encodings are rejected |
| `Permissive` | Accepts non-canonical payloads — for diagnostics only; never for production |

### Error codes

`VersionIncompatible` · `CapabilityMismatch` · `StrictModeRequired` · `ClockOutOfRange` · `NonCanonicalEncoding` · `DecodeRejected`

All errors are machine-readable and include human diagnostics and next-step guidance.

See [`docs/INTEROP_SPEC.md`](docs/INTEROP_SPEC.md) and [`docs/COMPATIBILITY_MATRIX.md`](docs/COMPATIBILITY_MATRIX.md).

---

## Network Administration Layer

`ssk-netadmin` + `ssk-netcore` together are the in-process replacement for external proxy software, controlled through `sskd` and the SSK CLI. The split is deliberate: `ssk-netadmin` **plans** (policy-driven, adapter-free, `no_std`-friendly); `ssk-netcore` **executes** (real sockets, real handshakes).

```
ssk-runtime
    │
    ▼
┌─────────────────────────────────────────────────────┐
│                    ssk-netadmin  (planning)         │
│  Flow Intake ──► Policy Engine ──► Route Orchestr. │
│       │               │                  │          │
│       ▼               ▼                  ▼          │
│  Attestation      Session Ledger    RouteCandidate  │
│  Binder           (hash-chain)      (which adapter, │
│       │                              which order)   │
│       └──────── Audit Ledger ◄───────────┘          │
│                  (hash-chain)                        │
└──────────────────────┬──────────────────────────────┘
                       │  RouteCandidate
                       ▼
┌─────────────────────────────────────────────────────┐
│                    ssk-netcore  (execution)         │
│  RouteExecutor: real TCP connect, real SOCKS5/HTTP  │
│  CONNECT handshake, real TLS handshake (OS trust    │
│  store), real DNS query — chained per hop           │
└──────────────────────┬──────────────────────────────┘
                       │  real socket
                       ▼
              the real destination
```

### Data-plane adapters

| Adapter | Protocol | Real execution |
|---------|---------|---------|
| `DirectAdapter` | Raw TCP | `ssk-netcore::direct` — real `TcpStream::connect` |
| `Socks5Adapter` | SOCKS5 | `ssk-netcore::socks5` — real RFC 1928/1929 client handshake |
| `HttpConnectAdapter` | HTTP CONNECT tunnel | `ssk-netcore::http_connect` — real request/response handshake |
| `TlsTunnelAdapter` | TLS-wrapped tunnel with SNI override | `ssk-netcore::tls` — real `rustls` handshake, OS-native trust store; mTLS client-cert wiring exists but has no config source yet |
| `DnsOverrideAdapter` | Split-horizon DNS resolution | `ssk-netcore::dns` — real UDP/TCP DNS query against the configured resolver |

`ssk-netadmin`'s adapter types remain descriptor-only by design (no network/async dependency, so the planning crate stays `no_std`-friendly); `ssk-netcore::RouteExecutor` is what actually dials out, given an `AdapterRegistry` mapping adapter ids to real transport config.

### Policy actions

`Allow` · `Deny` · `Redirect` · `SplitRoute` · `RequireAttestation` · `FailClosed` (implicit when no rule matches)

### Rollout modes

`Stable` · `Canary(percentage)` · `Shadow` · `Maintenance`

Every traffic decision is BLAKE3 hash-chained into an immutable `AuditLedger`, enabling deterministic forensic replay of all routing decisions.

**Not yet built**: automatic capture/classification of arbitrary local application traffic (that requires a separate, higher-privilege `ssk-capture` layer — OS-level traffic interception is a deliberately different, larger scope than adapter-level egress); true multi-hop proxy chaining beyond two hops is implemented but lightly exercised; a system-wide kill switch that blocks traffic at the OS network-stack level (today, "kill switch" tears down the one session the daemon holds — see `ssk-daemon`).

See [`docs/NETADMIN_SPEC.md`](docs/NETADMIN_SPEC.md).

---

## Development

### Build

```bash
cargo build --workspace
```

### Test

```bash
# Full test suite
cargo test --workspace

# Property-based tests (higher case count)
PROPTEST_CASES=32 cargo test --workspace

# Specific crate suites
cargo test -p ssk-interop          # interop contracts + conformance
cargo test -p ssk-netadmin         # netadmin contracts
cargo test -p ssk-faultscan        # chaos drills
cargo test -p ssk-config schema_snapshot_stable   # config schema guard
cargo test -p ssk-runtime --test replay_vectors   # replay integration
```

### Linting

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

### `no_std` check

```bash
cargo check -p ssk-types --no-default-features
cargo check -p ssk-core --no-default-features
```

### Runbook

Common incident scenarios and recovery steps are in [`docs/RUNBOOK.md`](docs/RUNBOOK.md):

- **Ledger mismatch** — stop writes, run `verify-ledger`, restore last good segment, re-verify before reopening.
- **Replay drift** — compare `run_id`/`replay_id`/`seeded`/`epoch`; isolate regression via deterministic test bisect.
- **Corrupted config** — run `config lint`; ensure `version=2`, `fail_closed=true`, `strict_mode=true`; restart only after lint success.
- **Capability mismatch** — align peer/local capability sets; keep strict mode; reattempt handshake.

---

## CI Matrix

| Job | What it checks |
|-----|---------------|
| `fmt_lint` | `cargo fmt` + `cargo clippy -D warnings` |
| `build_test` | `cargo build` + `cargo test` workspace-wide |
| `proptest_smoke` | Property tests at `PROPTEST_CASES=32` |
| `replay_vectors` | Deterministic replay integration tests |
| `interop_contracts` | Interop golden, negative, and fuzz tests |
| `conformance_suite` | 7-profile interop conformance suite |
| `config_schema_guard` | Schema snapshot stability + schema export |
| `breaking_change_guard` | Contract-surface change detection on PRs |
| `netadmin_contracts` | Network administration layer contracts |
| `chaos_drills` | Full fault-injection playbook via `ssk-faultscan` |
| `no_std_core` | `ssk-types` + `ssk-core` no-default-features check |
| `cargo_audit` | Deny all RustSec advisories |
| `cargo_deny` | License allow-list, banned dependencies, crates.io-only sources |

---

## Release

- **Versioning**: [Semantic Versioning](https://semver.org/)
- **Commits**: [Conventional Commits](https://www.conventionalcommits.org/) recommended (`feat:`, `fix:`, `docs:`, …)
- **Artifacts**: GitHub Actions release workflow packages platform binaries and a crate source archive
- **Updates**: Dependabot opens automated PRs for Cargo and GitHub Actions on a weekly schedule

---

## Roadmap

### P1 — Next
- Signed capability attestations and cryptographic handshake binding
- Multi-peer interop conformance suite across independent implementations
- Extended `doctor` checks (network, file-lock contention, entropy fallback on non-Unix)

### P2 — Later
- Formal compatibility policy engine with deprecation windows
- Long-horizon chaos/recovery simulations and forensic tooling automation
- Advanced accessibility mode (screen-reader-first command output profile)
- Desktop GUI (Tauri) — runtime control panel, gate-report viewer, replay diff inspector

See [`docs/EVOLUTION_STAGE_2_REPORT.md`](docs/EVOLUTION_STAGE_2_REPORT.md) and [`docs/ROADMAP_DESKTOP_GUI.md`](docs/ROADMAP_DESKTOP_GUI.md).

---

## Contributing

- Small, reviewable pull requests.
- Keep CI green before merge.
- Add/adjust tests for behavior changes.
- Document non-trivial decisions in `docs/adr/`.
- Use conventional commit messages.

See [`CONTRIBUTING.md`](CONTRIBUTING.md) and [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

---

## Documentation

| Document | Description |
|----------|-------------|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Module separation, data path, observability path, netadmin diagram |
| [`docs/OPERATIONS.md`](docs/OPERATIONS.md) | Operational commands and CI matrix summary |
| [`docs/INTEROP_SPEC.md`](docs/INTEROP_SPEC.md) | Wire format, version/capability negotiation, error codes |
| [`docs/COMPATIBILITY_MATRIX.md`](docs/COMPATIBILITY_MATRIX.md) | Protocol version compatibility table |
| [`docs/NETADMIN_SPEC.md`](docs/NETADMIN_SPEC.md) | Network administration layer full specification |
| [`docs/RUNBOOK.md`](docs/RUNBOOK.md) | Incident response playbooks |
| [`docs/UX_GUIDELINES.md`](docs/UX_GUIDELINES.md) | CLI UX principles and accessibility guidelines |
| [`docs/EVOLUTION_STAGE_2_REPORT.md`](docs/EVOLUTION_STAGE_2_REPORT.md) | Stage-2 gap analysis, roadmap, and implemented artifacts |
| [`docs/adr/`](docs/adr/) | Architecture Decision Records |
| [`SECURITY.md`](SECURITY.md) | Security policy, vulnerability reporting, chaos drill coverage |

