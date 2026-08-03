# ScorpioSync-Kaleidoscorp Ω

**Production-oriented, pure Rust runtime** implementing the ScorpioSync-Kaleidoscorp Ω master specification.

[![CI](https://github.com/LashSesh/kaleidoscorp.io/actions/workflows/ci.yml/badge.svg)](https://github.com/LashSesh/kaleidoscorp.io/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](#license)

> **Current status of record:** [`docs/WINDOWS_PRODUCT_ROADMAP.md`](docs/WINDOWS_PRODUCT_ROADMAP.md)
> (2026-08-02) is the source of truth for what this workspace does and does not do. It was written
> from the first execution of this repo on real Windows 11 hardware and supersedes the
> forward-looking sections of the root-level audit registers. Read it before trusting any
> capability claim on this page.

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
16. [License](#license)

---

## Overview

ScorpioSync-Kaleidoscorp Ω (SSK Ω) is a deterministic, replay-verifiable runtime with fail-closed enforcement at every layer. It provides:

- **Deterministic execution** — every pipeline run is fully replayable via BLAKE3 hash-chained manifests.
- **Fail-closed gate vector** — a 12-gate enforcement system; any gate failure halts the pipeline immediately.
- **Canonical wire format** — strict CBOR encoding with BLAKE3 content-addressing (SHA-256 compatibility available).
- **Versioned interoperability** — explicit version/capability negotiation with strict decode guards.
- **Production-grade CLI** — structured JSON output, unified exit-code taxonomy, and self-diagnostic tooling.
- **Policy-driven outbound egress** — a real, cryptographically-audited (BLAKE3 hash-chained) decision path from a policy engine to a real socket: Direct/SOCKS5/HTTP-CONNECT/TLS egress and DNS-override resolution (`ssk-netcore`), dispatched through the daemon (`sskd`). This is *dialing under policy*, not traffic interception — see the note below.

> **Honest maturity note.** The decision/audit/planning core (Intent→Orbit→Locator→BCIK→GateVector→Tensor→Focus→Replay) is real, deterministic, and heavily tested. `ssk-netcore` is real: genuine TCP, RFC 1928/1929 SOCKS5, HTTP-CONNECT, `rustls` TLS and DNS handshakes, tested against live listeners.
>
> **There is no traffic ingress.** This is not a Proxifier replacement today and the README previously implied otherwise. Nothing in the tree captures, intercepts or redirects another application's traffic: there is no proxy listener, no WFP/WinDivert/LSP/TUN hook, no PAC file and no proxy-settings writer. `ssk activate` requires an operator-typed `--dest host:port`, opens exactly one TCP connection to it, and **writes zero bytes through it** — `EgressSession::transport_mut` (`crates/ssk-netcore/src/session.rs:63`) has no callers of any kind. `ssk-capture` has no OS capture; its only production `TrafficSource` is a hardcoded CLI fixture.
>
> Also **not** built: a desktop GUI (`ssk-tauri-bridge` is a leaf crate with no consumers in either direction and no Tauri scaffold), systemd/launchd units, and a config-driven multi-profile model. A Windows netsh-based kill-switch *does* exist in `ssk-winhost` and is reachable as `ssk winhost killswitch engage`, but no successful engage→release cycle has ever been observed on any machine, and on non-English Windows it aborts before adding a rule (locale-literal parsing). Building ingress and dispatch is P4 of [`docs/WINDOWS_PRODUCT_ROADMAP.md`](docs/WINDOWS_PRODUCT_ROADMAP.md); that document, not this one, carries the current status.

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

**User-reachable path (Unix only today)**: `ssk activate --profile <p> --dest host:port` (`ssk-cli`) → real Unix-socket IPC → `sskd` (`ssk-daemon`) evaluates the real policy engine, plans a real route, and drives `ssk-netcore` to really connect. `Protected` is reported only after a real handshake succeeds; `FailClosed` is reported — with a real, typed reason — otherwise. `ssk deactivate` really tears the session down. The session carries no application bytes (see the maturity note above).

> **On Windows this path is currently unreachable.** The daemon's named-pipe *server* works — `sskd.exe` binds `\\.\pipe\kaleidoscorp-sskd` and has been driven end-to-end from an external client — but no named-pipe *client* exists in the tree, so `ssk status`/`activate`/`deactivate`/`list-profiles` return `error(Runtime/12): daemon-backed commands use a Unix domain socket` even while the daemon is running and its pipe is bound. Writing that client is P2 of [`docs/WINDOWS_PRODUCT_ROADMAP.md`](docs/WINDOWS_PRODUCT_ROADMAP.md).

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
| `ssk-ipc` | Request/response protocol between `ssk-cli` and `sskd`. Unix-socket server **and** client; Windows named-pipe **server only** — the server is verified working on Windows 11, but no named-pipe client exists yet (P2) |
| `ssk-daemon` | `sskd` — the real local system service: state machine, policy-driven activation, real `ssk-netcore`-backed egress, persisted audit ledger |
| `ssk-cli` | Operator UX (`doctor`, `explain`, `--json`, config tooling, `activate`/`deactivate`/`status`, netadmin commands) |

> **`no_std` note**: `ssk-types` and `ssk-core` are `no_std`-friendly and verified in CI via `cargo check --no-default-features`.

> **This table is not the whole workspace.** It covers 24 of the 44 crates in `crates/`. The other 20 —
> `ssk-audit-store`, `ssk-boundary`, `ssk-capture`, `ssk-crown`, `ssk-delivery`, `ssk-field-tensor`,
> `ssk-funnel-dag`, `ssk-host-cells`, `ssk-imdf`, `ssk-meta-resonance`, `ssk-mpk`, `ssk-netd-helper`,
> `ssk-profile-manifold`, `ssk-service-host`, `ssk-signature`, `ssk-system`, `ssk-tauri-bridge`,
> `ssk-tfa`, `ssk-topology-scalpel`, `ssk-winhost` — are Windows-host, privileged-broker, GUI-bridge
> and analysis crates. Per the 2026-08-02 reachability audit
> ([`docs/WINDOWS_PRODUCT_ROADMAP.md` §1.5](docs/WINDOWS_PRODUCT_ROADMAP.md)) roughly 29% of the
> workspace's `src` LOC links into **no shipped binary at all**; notably `ssk-netd-helper` (the
> privileged broker) declares no `[[bin]]` and is constructed only from test files, and
> `ssk-tauri-bridge` has zero consumers in either direction. Splitting the workspace is P5.

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
| `activate --profile <p> --dest <host:port>` | Ask `sskd` to really connect to `host:port` via the policy-decided route; `Protected` only on real success. The connection is opened and held; no application bytes are written through it |
| `deactivate` | Really tear down the live egress session and return to `Inactive` |
| `list-profiles` | List profiles known to the daemon (currently one reference profile; a config-driven multi-profile model is future work) |
| `system run` | Run the `ssk-system` Crown pipeline over a deterministic fixture and print the fail-closed verdict |
| `winhost capture` | Enumerate real active TCP/UDP flows via IP Helper (Windows; works unelevated) |
| `winhost killswitch engage` / `release` | Sever / restore outbound egress via `netsh` and persist a rollback receipt (Windows, Administrator) |
| `winhost service install` / `start` / `stop` / `uninstall` | Windows Service Control Manager lifecycle for the `ssk-svc` host (Administrator) |

Every error output includes a machine code, error class, exit code, and actionable next steps. Use `ssk explain <error>` for extended diagnostics.

`status`/`activate`/`deactivate`/`list-profiles` require `sskd` to be running (`cargo run -p ssk-daemon --bin sskd`); they exit with a clear `IPC_CONNECT_FAILED`-class error otherwise, never a silent success.

**Known-broken on Windows** (all P2 in [`docs/WINDOWS_PRODUCT_ROADMAP.md`](docs/WINDOWS_PRODUCT_ROADMAP.md), all observed by running them on Windows 11 on 2026-08-02):

- `status`/`activate`/`deactivate`/`list-profiles` always fail — there is no named-pipe client, so they return `error(Runtime/12)` even with `sskd` running.
- `doctor` always exits 16 — it probes `/dev/urandom` unconditionally, so the entropy check cannot pass on Windows regardless of the machine's actual state.
- `ssk --version` errors out — the clap derive carries no `version` attribute.
- `winhost killswitch engage` fails on non-English Windows before adding any rule, because `netsh` output is matched against English literals. The emitted "requires Administrator" next-step is misleading in that case.

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

`ssk-netadmin` + `ssk-netcore` together are the policy-driven **outbound egress** layer, controlled through `sskd` and the SSK CLI. The split is deliberate: `ssk-netadmin` **plans** (policy-driven, adapter-free, `no_std`-friendly); `ssk-netcore` **executes** (real sockets, real handshakes).

> **Scope, stated plainly:** this layer decides how to reach a destination *the operator names* and then really reaches it. It is **not** a replacement for external proxy software such as Proxifier, because it never sees another application's traffic. The ingress side — a local SOCKS5/HTTP-CONNECT listener, then a WFP/WinDivert redirect layer — is P4 of [`docs/WINDOWS_PRODUCT_ROADMAP.md`](docs/WINDOWS_PRODUCT_ROADMAP.md) and is not started.

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

**Not yet built**:

- **Traffic ingress of any kind.** No proxy listener, no WFP/WinDivert/LSP/TUN hook, no PAC, no proxy-settings writer. `ssk-capture` has no OS capture; its only production `TrafficSource` is a hardcoded CLI fixture. (`ssk winhost capture` does enumerate real live flows via IP Helper, but that is observation, not interception, and it does not feed this layer.)
- **Byte transfer.** `EgressSession::transport_mut` (`crates/ssk-netcore/src/session.rs:63`) has zero callers, so no application data crosses an established session.
- **Real flow classification.** The supervisor hardcodes `RiskLevel::Low` / `ProtocolKind::Tcp`, so every non-`Direct` executor path is structurally unreachable in production.
- **Config-driven routing.** The loaded `AppConfig` is not passed into `Supervisor::new`; the adapter registry is hardcoded.
- True multi-hop proxy chaining beyond two hops is implemented but lightly exercised.
- A daemon-level "kill switch" only tears down the one session the daemon holds. The separate OS-level kill-switch (`ssk winhost killswitch`, netsh firewall rules) exists but has never been observed completing an engage→release cycle on any machine, in any locale.

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
| `windows_backends` | Builds/lints/tests `ssk-winhost` and builds `ssk-cli` with the real MSVC toolchain |
| `windows_crate_gates` | Per-crate Windows build + clippy + test for `ssk-ipc`, `ssk-daemon`, `ssk-netd-helper`, `ssk-tauri-bridge` |

### Platform coverage

This table lists *what* each job checks; it has historically been read as implying the whole
workspace is checked on every platform, which it was not.

**Before P0** (measured 2026-08-02, on the first run of this workspace on real Windows 11 hardware):
13 of 14 jobs ran on `ubuntu-latest`, and the single `windows-latest` job built, linted and tested
exactly **one** of the 44 crates. No Windows-only regression in `ssk-ipc`, `ssk-daemon`,
`ssk-netd-helper` or `ssk-tauri-bridge` could have been caught, and none of the four gates was
enforced on Windows at all — where, when actually run, all four failed.

**Now**: `fmt_lint`, `build_test`, `proptest_smoke` and `config_schema_guard` run on an
`[ubuntu-latest, windows-latest]` matrix, so all four gates —
`cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
`cargo build --workspace --all-targets` and `cargo test --workspace` — are enforced on Windows;
and `windows_crate_gates` adds a per-crate Windows leg for the four previously-uncovered crates.

Two caveats, so the badge is not over-read:

1. **The `windows_crate_gates` result has not been observed yet.** `ssk-netd-helper` fails 8 of its
   12 `p0_broker` tests on an *unelevated* Windows box; a GitHub runner executes as administrator,
   so this job is deliberately an open experiment — see
   [`docs/WINDOWS_PRODUCT_ROADMAP.md`](docs/WINDOWS_PRODUCT_ROADMAP.md) §5.2. A red result there is
   the answer being asked for, not a badge problem.
2. `replay_vectors`, `interop_contracts`, `conformance_suite`, `netadmin_contracts`, `chaos_drills`,
   `no_std_core`, `cargo_audit`, `cargo_deny` and `breaking_change_guard` still run on
   `ubuntu-latest` only.

`.github/workflows/ci.yml` is authoritative for what actually runs.

---

## Release

- **Versioning**: [Semantic Versioning](https://semver.org/)
- **Commits**: [Conventional Commits](https://www.conventionalcommits.org/) recommended (`feat:`, `fix:`, `docs:`, …)
- **Artifacts**: **source archive only.** `.github/workflows/release.yml` builds `--release` on `ubuntu-latest` and then tars `crates Cargo.toml README.md docs` — the compiled `ssk`/`sskd` binaries are discarded and never uploaded. There is no Windows or macOS artifact, no checksum file and no SBOM. A matrix build that ships real, signed binaries is P6 of [`docs/WINDOWS_PRODUCT_ROADMAP.md`](docs/WINDOWS_PRODUCT_ROADMAP.md). To obtain runnable binaries today you must build from source.
- **Reproducibility**: until P0 a build was not a reproducible statement — `Cargo.lock` was gitignored and there was no toolchain pin, no declared MSRV and no explicit release profile. P0 addressed all four: `Cargo.lock` is no longer ignored, `rust-toolchain.toml` pins the toolchain, `Cargo.toml` declares `rust-version` under `[workspace.package]`, and `[profile.release]` is explicit. **One caveat, stated by that change itself:** no member manifest yet sets `rust-version.workspace = true` and no CI leg builds on the MSRV, so the declared MSRV is a claim about the resolved dependency graph — this workspace's own sources have never been compiled by that toolchain.
- **Updates**: Dependabot opens automated PRs for Cargo and GitHub Actions on a weekly schedule

---

## Roadmap

**[`docs/WINDOWS_PRODUCT_ROADMAP.md`](docs/WINDOWS_PRODUCT_ROADMAP.md) is the current, authoritative
plan.** It is ordered P0→P7 and every status claim in it was produced by executing something on real
Windows 11 hardware on 2026-08-02:

| Phase | Goal |
|---|---|
| **P0** | Make the truth measurable — the four gates compile and run on Windows; a build becomes reproducible |
| **P1** | Stop the bleeding in the privileged layer (receipt forgery, user-writable SYSTEM service image, locale-dependent netsh) |
| **P2** | Make the product reachable on Windows — named-pipe client, pipe SID auth, `--version`, working `doctor` |
| **P3** | Host the privileged broker for real, so `ssk-netd-helper` has a process to live in |
| **P4** | Build the actual product promise: traffic ingress and byte dispatch |
| **P5** | Make the analysis honest and connected (PID-attributed dual-stack capture; no unconditionally-satisfied gates) |
| **P6** | Distribution and operability — matrix release, `LICENSE`, MSI installer, Authenticode signing, updater |
| **P7** | Desktop GUI — deliberately last, because a panel built earlier could only display a fabricated green |

The roadmap also records three security findings (two Critical) that gate distribution, and a §6
**scope decision** — whether the product keeps transparent interception (making P4 unavoidable) or
re-scopes to a deterministic analysis/audit tool with a real kill-switch — that should be made
before P1 starts.

Older, superseded planning documents: [`docs/EVOLUTION_STAGE_2_REPORT.md`](docs/EVOLUTION_STAGE_2_REPORT.md),
[`docs/ROADMAP_DESKTOP_GUI.md`](docs/ROADMAP_DESKTOP_GUI.md).

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
| [`docs/WINDOWS_PRODUCT_ROADMAP.md`](docs/WINDOWS_PRODUCT_ROADMAP.md) | **Source of truth.** Measured Windows status, security findings, the P0–P7 plan, and the open questions |
| [`RELEASE_BLOCKER_REGISTER.md`](RELEASE_BLOCKER_REGISTER.md) · [`PRODUCT_CONTRACT_MATRIX.md`](PRODUCT_CONTRACT_MATRIX.md) | Dated audit artifacts (2026-07-04). Read their status boxes first — several entries have since changed in **both** directions |
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

---

## License

This workspace declares `license = "Apache-2.0"` in `Cargo.toml` (`[workspace.package]`).

> **The full licence text is not yet in the tree.** There is no `LICENSE` file at the repository
> root, and no `NOTICE`. The badge above therefore links to this section rather than to a file that
> does not exist. Adding the complete Apache-2.0 text plus a `NOTICE`, and shipping both inside every
> release artifact, is P6 of [`docs/WINDOWS_PRODUCT_ROADMAP.md`](docs/WINDOWS_PRODUCT_ROADMAP.md).
> Until that lands, the declared licence is an intent recorded in metadata, not a distributed grant.

