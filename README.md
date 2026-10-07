# ScorpioSync-Kaleidoscorp Ω

**Production-oriented, pure Rust runtime** implementing the ScorpioSync-Kaleidoscorp Ω master specification.

[![CI](https://github.com/LashSesh/kaleidoscorp.io/actions/workflows/ci.yml/badge.svg)](https://github.com/LashSesh/kaleidoscorp.io/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](#license)

> **Current status (2026-09-22):** Start with the
> [restart assessment](docs/RESTART_ASSESSMENT_2026-09-21.md) and
> [routing/OpenVPN implementation status](docs/ROUTING_AND_OPENVPN_STATUS.md).
> The daemon now uses configured v4 routing profiles and enforced admission.
> The [OpenVPN management library](docs/OPENVPN_MANAGEMENT.md),
> [protected profiles and Windows process containment](docs/OPENVPN_PROFILES_AND_PROCESS.md)
> are now composed into a [verified, held startup](docs/OPENVPN_SECURE_START.md).
> [Audited broker commands and service supervision](docs/OPENVPN_BROKER_CONTROL.md)
> now prepare/stop held sessions, support [audited crash recovery](docs/OPENVPN_RECOVERY.md)
> and preserve [segmented journal history](docs/OPENVPN_JOURNAL_RETENTION.md).
> [Protected journal snapshots](docs/OPENVPN_JOURNAL_BACKUP.md) can be exported and
> verified against independently retained expectations; live journal restoration remains open.
> [Recovery into quarantine](docs/OPENVPN_JOURNAL_BACKUP.md#reconstruct-in-blocked-quarantine)
> now preserves damaged originals and fences service startup; candidate activation remains open.
> [Offline package staging, selection and recovery](docs/OPENVPN_PACKAGE_DEPLOYMENT.md)
> now provide the pinned-bundle update layer; full installation and VM acceptance remain open.
> [Profiles and per-SID grants](docs/OPENVPN_CONFIGURATION_DEPLOYMENT.md) can now
> be installed as one audited configuration and held consistently for each service run.
> [Offline diagnosis and exact restoration](docs/OPENVPN_CONFIGURATION_RESTORE.md)
> can recover the committed configuration while preserving evidence and process recovery state.
> [Encrypted configuration backups](docs/OPENVPN_CONFIGURATION_BACKUP.md) support
> separate recovery keys, archive verification and restoration without a plaintext import file.
> The [VM evidence recorder](docs/OPENVPN_ACCEPTANCE_TOOL.md) tracks reviewed attempts
> and verifies both locale runs; actual privileged acceptance remains pending.
> A [development test kit](docs/OPENVPN_TEST_KIT.md) packages the reviewed binaries
> and checks transfer integrity; a read-only host probe supports planning a future VM.
> VPN activation still awaits tunnel enforcement and [VM acceptance](docs/OPENVPN_VM_ACCEPTANCE.md). This is
> a development build; held daemon egress does not imply system-wide protection.
> The [Windows roadmap](docs/WINDOWS_PRODUCT_ROADMAP.md) remains the longer-term plan.

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
- **Fail-closed gate vector — in the *decision core only*, not a product capability.** A 12-gate
  vector guards the deterministic pipeline, and any gate failure halts *that pipeline*. It does not
  guard traffic: `sskd` never calls `ssk_runtime::run_to_outcome`, and `ssk-daemon` does not depend
  on `ssk-runtime` at all (`crates/ssk-daemon/Cargo.toml:11-47`). The vector is reachable only from
  `ssk-cli`'s `run` / `replay-verify` / `connect` subcommands, each of which drives a hardcoded
  `sample_intent(valid_fixture)` fixture rather than a real connection
  (`crates/ssk-cli/src/main.rs:3967`, `:4031`, `:4101`). See
  [ADR 0008](docs/adr/0008-flow-path-owns-the-per-connection-decision.md) for why this is structural
  and not a wiring oversight, and `docs/WINDOWS_PRODUCT_ROADMAP.md:186-194` (§3(b), with the dated
  correction attached to it) for the recorded history of gates in this vector that could not fail.
- **Canonical wire format** — strict CBOR encoding with BLAKE3 content-addressing (SHA-256 compatibility available).
- **Versioned interoperability** — explicit version/capability negotiation with strict decode guards.
- **Production-grade CLI** — structured JSON output, unified exit-code taxonomy, and self-diagnostic tooling.
- **Policy-driven outbound egress** — a real, cryptographically-audited (BLAKE3 hash-chained) decision path from a policy engine to a real socket: Direct/SOCKS5/HTTP-CONNECT/TLS egress and DNS-override resolution (`ssk-netcore`), dispatched through the daemon (`sskd`). This is *dialing under policy*, not traffic interception — see the note below.

> **Honest maturity note.** The decision/audit/planning core (Intent→Orbit→Locator→BCIK→GateVector→Tensor→Focus→Replay) is real, deterministic, and heavily tested. `ssk-netcore` is real: genuine TCP, RFC 1928/1929 SOCKS5, HTTP-CONNECT, `rustls` TLS and DNS handshakes, tested against live listeners.
>
> **There is no traffic ingress.** This is not a Proxifier replacement today and the README previously implied otherwise. Nothing in the tree captures, intercepts or redirects another application's traffic: there is no proxy listener, no WFP/WinDivert/LSP/TUN hook, no PAC file and no proxy-settings writer. `ssk activate` requires an operator-typed `--dest host:port`, opens exactly one TCP connection to it, and **writes zero bytes through it** — `EgressSession::transport_mut` (`crates/ssk-netcore/src/session.rs:63`) has no callers of any kind. `ssk-capture` has no OS capture; its only production `TrafficSource` is a hardcoded CLI fixture.
>
> Desktop update (2026-09-24): a [Windows diagnosis UI](apps/desktop/README.md) now reads daemon status; system-wide verified protection and control remain pending. A Windows netsh-based kill-switch exists in `ssk-winhost`, but a successful engage→release cycle still needs isolated-machine acceptance. Building ingress and dispatch is P4 of the [Windows roadmap](docs/WINDOWS_PRODUCT_ROADMAP.md); configuration and OpenVPN progress are recorded in the [restart assessment](docs/RESTART_ASSESSMENT_2026-09-21.md).

---

## Architecture

Two distinct paths share this workspace, and they are **parallel, not stacked**. Neither calls the
other: `ssk-runtime` and `ssk-netadmin` have no dependency relationship in *either* direction
(`crates/ssk-runtime/Cargo.toml:7-24` does not name `ssk-netadmin`;
`crates/ssk-netadmin/Cargo.toml:15-23` does not name `ssk-runtime`; confirm with
`cargo tree -p ssk-daemon --edges normal`).
[ADR 0008](docs/adr/0008-flow-path-owns-the-per-connection-decision.md) is the authority for this
split and records why it is structural.

> **Diagram correction (2026-08-11).** The diagram previously in this section drew a data-flow edge
> from `ssk-runtime` into `ssk-netadmin`. That edge has never existed, in either direction. It is
> replaced below rather than deleted, so the two real paths are both visible.

**Path 1 — the live per-connection path.** The only path on which a policy decision reaches a real
socket. `ssk-cli` never constructs a `RouteExecutor` or a `NetcoreDataPlane` itself; only `sskd` does
(`crates/ssk-daemon/src/main.rs:272-273`).

```
ssk-cli  ──IPC──►  sskd  (ssk-daemon)
                     │
                     │  FlowDescriptor
                     ▼
         ┌──────────────────────────┐
         │       ssk-netadmin       │  ← policy-driven route *planning*
         │  FlowDescriptor          │    (real, tested, adapter-free,
         │   → PolicyEngine         │     no network I/O)
         │   → RouteOrchestrator    │
         │   → Attestation / Audit  │
         └────────────┬─────────────┘
                      │  RouteCandidate → RouteKind
                      ▼
         ┌──────────────────────────┐
         │        ssk-netcore       │  ← policy-planned route *execution*
         │  RouteExecutor: real     │
         │  Direct / SOCKS5 / HTTP  │
         │  CONNECT / TLS / DNS     │
         │  + real health probing   │
         └────────────┬─────────────┘
                      │  real socket
                      ▼
             (the actual destination)
```

Verified call sites: `crates/ssk-daemon/src/supervisor.rs:541-558` builds the `FlowDescriptor` and
runs `engine.evaluate(&flow)` then `orchestrator.plan(&flow, &decision)`;
`crates/ssk-daemon/src/supervisor.rs:582` dispatches it via `data_plane.connect_route(...)` over the
real `NetcoreDataPlane`/`RouteExecutor` constructed in production at
`crates/ssk-daemon/src/main.rs:272-273`.

**Path 2 — the decision core.** A separate path with its own entry point, reachable only from
`ssk-cli`. Nothing on Path 1 calls into it.

```
ssk-cli   `run` | `replay-verify` | `connect`
                     │
                     │  sample_intent(valid_fixture)
                     │  — a hardcoded fixture, not a real connection
                     ▼
   ┌──────────────────────────────────────────────────┐
   │  ssk-runtime  (with ssk-gates, ssk-bcik, ssk-imdf,│
   │               ssk-locator, ssk-focus, ssk-tensor) │
   │  Intent → Orbit → Locator → BCIK → GateVector →   │
   │  Tensor → Focus → Replay                          │
   │  no network I/O, no adapters, no sockets          │
   └──────────────────────────────────────────────────┘
```

Verified entry points: the `Run` / `ReplayVerify` / `Connect` subcommands
(`crates/ssk-cli/src/main.rs:206`, `:214`, `:225`), dispatched at
`crates/ssk-cli/src/main.rs:802`, `:808`, `:813`. The workspace's only production caller of
`ssk_runtime::run_to_outcome` is `connect_command` (`crates/ssk-cli/src/main.rs:4030-4031`).

**User-reachable path**: `ssk activate --profile <p> --dest host:port` (`ssk-cli`) → real IPC (Unix domain socket on Unix, named pipe on Windows) → `sskd` (`ssk-daemon`) evaluates the real policy engine, plans a real route, and drives `ssk-netcore` to really connect. `Protected` is reported only after a real handshake succeeds; `FailClosed` is reported — with a real, typed reason — otherwise. `ssk deactivate` really tears the session down. The session carries no application bytes (see the maturity note above).

> **Windows reachability (corrected 2026-08-11).** This README previously said the control plane was unreachable on Windows because no named-pipe *client* existed. That is no longer true: `DaemonClient::connect` dispatches on the endpoint variant and `Endpoint::NamedPipe` is a real, implemented arm (`crates/ssk-ipc/src/client.rs:34`, `:49-53`), and `ssk-cli` derives the pipe endpoint from this process's SID (`crates/ssk-cli/src/main.rs:666-668`). The endpoint is no longer a fixed global name either — it is a digest over `(scheme, version, user SID, state directory)`, so two users' daemons cannot address each other. P2 of [`docs/WINDOWS_PRODUCT_ROADMAP.md`](docs/WINDOWS_PRODUCT_ROADMAP.md) is recorded **DONE** (`:477`).

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
| `ssk-netadmin` | In-process network administration layer: policy-driven route **planning** (adapter-free, no network I/O) |
| `ssk-netanalysis` | Bounded offline behavioral analysis and replay tool; advisory only, no capture or connection authority ([status](docs/NETWORK_ANALYSIS_BASELINE.md)) |
| `ssk-netcore` | Real route **execution**: Direct/SOCKS5/HTTP-CONNECT/TLS egress, DNS-override resolution, health probing |
| `ssk-ipc` | Request/response protocol between `ssk-cli` and `sskd`. Server **and** client on both transports: Unix domain socket and Windows named pipe (`DaemonClient::connect` dispatches on the `Endpoint` variant, `crates/ssk-ipc/src/client.rs:49-53`). *Corrected 2026-08-11 — this row previously said "server only"; the client landed in P2.* |
| `ssk-daemon` | `sskd` — the real local system service: state machine, policy-driven activation, real `ssk-netcore`-backed egress, persisted audit ledger |
| `ssk-cli` | Operator UX (`doctor`, `explain`, `--json`, config tooling, `activate`/`deactivate`/`status`, netadmin commands) |

The standalone `ssk-netobserve` tool provides bounded, read-only Windows TCP/UDP
IPv4/IPv6 diagnostics for one process. It reports endpoints and missing capabilities;
it does not feed the behavioral baseline or change network policy.
See [Windows network observation](docs/WINDOWS_NETWORK_OBSERVATION.md).
Its `etw-replay` command also validates bounded kernel-network event exports using
Windows TDH; this is offline diagnostic decoding, with explicit loss handling and
no live trace session ([status](docs/ETW_NETWORK_DECODER.md)).
The `etl` command reads existing local ETL files in a supervised Windows worker
with time, memory, event and output limits; imported files remain unverified
([status](docs/ETL_NETWORK_READER.md)).
File-local process lifecycle correlation distinguishes observed starts, rundown,
PID reuse and missing evidence without claiming verified identity
([status](docs/ETL_PROCESS_CORRELATION.md)).
The `etl-check` command binds an untrusted controller closure to the ETL file by
SHA-256 and checks declared configuration, stop results and loss counters;
consistent input remains unverified ([contract and acceptance](docs/ETL_RECORDING_CLOSURE.md)).
`ssk-netcapture` provides a private in-process ETL fixture and fixed IPv4/IPv6
TCP/UDP loopback workload. Its system-capture plan is read-only; no system logger
can be started ([capture preparation](docs/ETW_CAPTURE_PREPARATION.md)).
Private capture now runs in a supervised worker with bounded time, memory and
output. Process exit and session cleanup remain separate evidence
([supervision and failure handling](docs/ETW_CAPTURE_SUPERVISION.md)).

The [desktop UI](ui/desktop/README.md) is an independent browser module with
separate view components, a versioned `ssk-ui-contract` and replaceable data
adapters. Run `npm --prefix ui/desktop run dev` for the explicitly labelled
fixture preview; no Rust build or running service is needed. The separate
[Windows Tauri host](apps/desktop/README.md) reads live daemon status through a
bounded local pipe client. Its v2 contract carries no verified protection claims
([backend boundaries](docs/DESKTOP_BACKEND_CONNECTION.md)).

> **`no_std` note**: `ssk-types` and `ssk-core` are `no_std`-friendly and verified in CI via `cargo check --no-default-features`.

> **This table is not the whole workspace.** It covers 23 of the 44 crates in `crates/`. The other 21 —
> `ssk-audit-store`, `ssk-boundary`, `ssk-capture`, `ssk-crown`, `ssk-delivery`, `ssk-diag`,
> `ssk-field-tensor`, `ssk-funnel-dag`, `ssk-host-cells`, `ssk-imdf`, `ssk-meta-resonance`,
> `ssk-mpk`, `ssk-netd-helper`,
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
| `net-admin flow-inspect` | Offline demo: classify against built-in sample rules, not daemon configuration |
| `net-admin route-trace` | Offline demo route plan; use `trace-route` for the daemon configuration |
| `net-admin audit-dump` | Generate and dump an in-memory demonstration ledger; not the persisted daemon audit |
| `status` | Query the real daemon (`sskd`) state over its IPC endpoint — Unix domain socket on Unix, named pipe on Windows |
| `activate --profile <p> --dest <host:port>` | Ask `sskd` to really connect to `host:port` via the policy-decided route; `Protected` only on real success. The connection is opened and held; no application bytes are written through it |
| `deactivate` | Really tear down the live egress session and return to `Inactive` |
| `list-profiles` | List the profiles of the daemon's validated startup configuration (without `SSK_CONFIG_PATH`: only the implicit `default` profile, which has no rules and denies everything) |
| `system run` | Run the `ssk-system` Crown pipeline over a deterministic fixture and print the fail-closed verdict |
| `winhost capture` | Enumerate real active TCP/UDP flows via IP Helper (Windows; works unelevated) |
| `winhost killswitch engage` / `release` | Sever / restore outbound egress via `netsh` and persist a rollback receipt (Windows, Administrator) |
| `winhost service install` / `start` / `stop` / `uninstall` | Windows Service Control Manager lifecycle for the `ssk-svc` host (Administrator) |

Every error output includes a machine code, error class, exit code, and actionable next steps. Use `ssk explain <error>` for extended diagnostics.

`status`/`activate`/`deactivate`/`list-profiles` require `sskd` to be running (`cargo run -p ssk-daemon --bin sskd`); they exit with a clear `IPC_CONNECT_FAILED`-class error otherwise, never a silent success.

**Previously known-broken on Windows — all four are now fixed** (observed broken on Windows 11 on
2026-08-02; closed by P1/P2 of [`docs/WINDOWS_PRODUCT_ROADMAP.md`](docs/WINDOWS_PRODUCT_ROADMAP.md),
which records P2 as **DONE** at `:477`). This section is retained rather than deleted, because it was
**stale-pessimistic** — it understated the product, which is the same class of documentation defect
as an overclaim and is corrected the same way:

| Was claimed broken | Actual state (verified 2026-08-11) |
|---|---|
| `status`/`activate`/`deactivate`/`list-profiles` always fail — no named-pipe client exists | **Fixed.** `DaemonClient::connect` has a real `Endpoint::NamedPipe` arm (`crates/ssk-ipc/src/client.rs:49-53`) over `tokio::net::windows::named_pipe::NamedPipeClient` (`:34`). |
| `doctor` always exits 16 — it probes `/dev/urandom` unconditionally | **Fixed.** The probe is now `getrandom::fill` (`crates/ssk-diag/src/entropy.rs:97`), which uses `ProcessPrng` on Windows and `getrandom(2)` on Linux; a regression test asserts the probe detail never names `/dev/urandom` (`crates/ssk-diag/src/entropy.rs:215-221`). |
| `ssk --version` errors out — the clap derive carries no `version` attribute | **Fixed.** `#[command(version = build::short(), long_version = build::long_version())]` (`crates/ssk-cli/src/main.rs:194`). |
| `winhost killswitch engage` fails on non-English Windows, because `netsh` output is matched against English literals | **Fixed.** `netsh` results are classified by exit code only: `parse_add_output` returns `Ok(())` iff `inv.is_success_exit()` and reads no prose at all (`crates/ssk-winhost/src/firewall.rs:670-679`, over `is_success_exit` at `:185-187`); its own doc comment at `:661-666` states why. `NetshError` has exactly one variant, because netsh collapses every failure mode into exit `1` (`:190-199`). Test: `add_is_exit_code_only`, `crates/ssk-winhost/src/firewall.rs:1626`. |

One claim that is **not** retracted: no successful `engage` → `release` cycle has been observed on
any machine (see the maturity note above). The locale defect is closed; the elevated end-to-end
validation is still outstanding, and the roadmap records P3 as `CODE COMPLETE … Elevated validation
outstanding` (`docs/WINDOWS_PRODUCT_ROADMAP.md:383`).

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

> **Scope, stated plainly:** this layer decides how to reach a destination *the operator names* and then really reaches it. It is **not** a replacement for external proxy software such as Proxifier, because it never sees another application's traffic. The ingress side is P4 of [`docs/WINDOWS_PRODUCT_ROADMAP.md`](docs/WINDOWS_PRODUCT_ROADMAP.md) and no sub-phase of it has started.
>
> **Corrected 2026-08-11.** This paragraph previously named "a local SOCKS5/HTTP-CONNECT listener,
> then a WFP/WinDivert redirect layer" as the planned mechanism. The roadmap superseded that on
> 2026-08-03 (`docs/WINDOWS_PRODUCT_ROADMAP.md:590-597`): **WFP/WinDivert is no longer the ingress
> mechanism.** The chosen design is a hybrid — Lane 1, a system-proxy SOCKS5/HTTP-CONNECT
> `TcpListener`; Lane 2, fake-IP DNS plus a *narrow-range* Wintun (TUN) adapter; Lane 3, OpenVPN as
> one additional subprocess-orchestrated adapter — with the dispatch model a per-flow smart router
> rather than a single-tunnel VPN client. See `docs/P4_INGRESS_DESIGN.md`.

```
sskd (ssk-daemon)
    │  FlowDescriptor
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

> **Diagram correction (2026-08-11).** This diagram previously showed `ssk-runtime` feeding
> `ssk-netadmin`. No such edge exists: neither crate depends on the other
> (`crates/ssk-runtime/Cargo.toml:7-24`, `crates/ssk-netadmin/Cargo.toml:15-23`), and the daemon
> builds the `FlowDescriptor` itself (`crates/ssk-daemon/src/supervisor.rs:544-552`). The
> `ssk-runtime` / `ssk-gates` / `ssk-bcik` decision core is a **separate** path with its own entry
> point (`ssk-cli`'s `run` / `replay-verify` / `connect`) — see
> [Architecture](#architecture), Path 2, and
> [ADR 0008](docs/adr/0008-flow-path-owns-the-per-connection-decision.md).

### Data-plane adapters

| Adapter | Protocol | Real execution |
|---------|---------|---------|
| `DirectAdapter` | Raw TCP | `ssk-netcore::direct`, through `ssk-netcore::connector` — real `TcpStream::connect` |
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
| `build_test` | `cargo build` + `cargo test` workspace-wide; the Linux leg sets `SSK_REQUIRE_IPV6=1`, so a runner without `::1` fails the IPv6 dial test instead of skipping it |
| `proptest_smoke` | Property tests at `PROPTEST_CASES=32` |
| `replay_vectors` | Deterministic replay integration tests |
| `interop_contracts` | Interop golden, negative, and fuzz tests |
| `conformance_suite` | 7-profile interop conformance suite |
| `config_schema_guard` | All `ssk-config` tests (schema snapshot stability included, no name filter) + schema export |
| `breaking_change_guard` | Fails a push or pull request that changes a contract surface (`scripts/ci/contract_surfaces.txt`) without a `docs/COMPATIBILITY_MATRIX.md` entry or a `Compat-Impact: none (<reason>)` commit trailer |
| `contract_guard_selftest` | `scripts/ci/tests/contract_guard.test.sh`: the guard's logic against throw-away repositories, on every push and pull request |
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
   `no_std_core`, `cargo_audit`, `cargo_deny`, `breaking_change_guard` and `contract_guard_selftest`
   still run on `ubuntu-latest` only.

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

