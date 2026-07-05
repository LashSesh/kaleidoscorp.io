# Architecture Completion Spec

> **IMPLEMENTATION UPDATE (post-audit, same day).** The `ssk-netcore` crate this document specifies as **missing** (§2.2) **now exists** at `crates/ssk-netcore/`, implementing the `RouteExecutor`/adapter seams this document defines: real Direct/SOCKS5/HTTP-CONNECT/TLS execution, real DNS-override resolution, real health probing. `ssk-daemon`'s `MockDataPlane` (§2.3, §3.2) has been replaced by `ssk_netcore::NetcoreDataPlane` in the production binary. The "today" data flow in §4.1 (terminates in an echo) is superseded for the `ssk activate --dest` path — see §4.2's "target" data flow, which is now real. `ssk-capture` (§2.2) remains genuinely absent. Treat every "MISSING"/"absent" statement about `ssk-netcore` specifically as historical; re-verify against `crates/ssk-netcore/` and `RELEASE_BLOCKER_REGISTER.md`'s update box before relying on any other claim in this document.

Target architecture for the SSKΩ ("Kaleidoscorp") system, and the honest gap between what the repository is today and what its product contract promises. This document is a corrective specification: it fixes the layer boundaries, names the crates that must exist, and defines the seams across which the missing "real network" capability must be added — without contaminating the deterministic core that already works.

Every "already exists" statement is anchored to `file:line`. Every "does not exist / not wired" statement cites the honesty marker in the code or the contradicting doc. Maturity is graded on a 0–7 ladder: **level 4** = locally executable, deterministic, tested code artifact; **level 5** = real system/network effect; **level 6** = packaged, user-reachable delivery.

---

## 0. Executive summary (what is true today)

- The repository is a **deterministic decision / audit / planning core plus a local IPC daemon skeleton**. As a *core code artifact* it is a solid **level 4**: it compiles (default features), it is deterministically tested, and it is honest in its own code comments about where it stops.
- As a *network / privacy product capability* it is **not** level 5. **No TCP/UDP/TLS/DNS packet leaves the process anywhere in the workspace.** The only real I/O is a same-host Unix-domain control socket, `/dev/urandom`, and local ledger files.
- The single terminal stage where a connection would touch a peer is `LocalFiberExecutor`, a deterministic local echo whose `payload_digest` is a Blake3 hash of the stitch's own fields (`crates/ssk-runtime/src/lib.rs:189-213`), documented as fabricating "no network liveness" (`crates/ssk-runtime/src/lib.rs:176-178`).
- The crate that would perform real egress — `ssk-netcore` — **does not exist** in the workspace (`ls crates/ssk-netcore` → no such directory). Neither does `ssk-capture` (traffic ingress).
- The product's own conformance ladder already admits this: **SSKΩ-7** (the one rung whose definition requires real egress adapters + health probing) is self-graded **⚠️ not met** and deferred to `ssk-netcore` (`docs/OMEGA_CORE_CONFORMANCE_SPEC.md:256`), which contradicts the summary claim at `:39` that "SSKΩ-0 through SSKΩ-9 are all met."
- Two hard falsifiers of any "production-ready / 100% done" claim:
  1. **SSKΩ-7 is unmet by its own text** (`docs/OMEGA_CORE_CONFORMANCE_SPEC.md:256`), and the crate it defers to is absent.
  2. **`cargo check -p ssk-core --no-default-features` fails** (E0425/E0433, "cannot find type `Vec`") at `crates/ssk-core/src/connection.rs:55,78,87` — bare `Vec` with no `use alloc::vec::Vec` — directly contradicting the README's CI-"verified" `no_std` guarantee (`README.md:102,342-343,371`).

This spec exists so the *real* work (a live data plane) can be added at the correct altitude, behind explicit seams, without weakening the deterministic core.

---

## 1. Target architecture (text diagram)

The target keeps a hard rule: **the core is deterministic and adapter-free; all real liveness lives in `ssk-netcore` and is owned operationally by `ssk-daemon`.** The core never opens a socket; it emits *decisions* and *plans* that a lower, impure layer executes and reports back through explicit, gated seams.

```
                         ┌───────────────────────────────────────────────────────────┐
                         │                     ssk-conformance                        │
                         │  model-property tests + (NEW) real end-to-end network tests │
                         │  drives every layer below; asserts real effect, not echo    │
                         └───────────────▲───────────────────────────▲────────────────┘
                                         │                           │
 ┌──────────────────────┐   ┌────────────┴───────────┐   ┌───────────┴────────────────────┐
 │      ssk-cli         │   │     ssk-desktop        │   │           ssk-daemon            │
 │  (ssk binary)        │   │   (NEW, optional)      │   │            (sskd)               │
 │  materialize/replay/ │   │  Tauri dashboard over  │   │  owns live state, supervision,  │
 │  doctor/explain/     │──▶│  the SAME IPC surface  │──▶│  kill-switch, config, capture,  │
 │  config/status/...   │   │  (no privileged core)  │   │  and the REAL data plane        │
 └──────────┬───────────┘   └────────────────────────┘   └───────┬──────────────┬──────────┘
            │ (local, in-proc, no daemon)                        │ IPC (Unix)   │ owns
            │                                                     │ real socket  │
            ▼                                                     ▼              ▼
 ┌───────────────────────────────────────────────┐   ┌────────────────┐  ┌────────────────────────┐
 │                   ssk-core*                    │   │   ssk-capture  │  │       ssk-netcore      │
 │  DETERMINISTIC, ADAPTER-FREE decision core     │   │  (NEW): traffic│  │  (NEW): REAL egress    │
 │  scheduler · identity · locator(model) · stitch│   │  ingress →     │  │  RouteExecutor over    │
 │  gates(12) · bcik crossing · tensor · focus    │◀──│  FlowRecord    │  │  Direct/SOCKS5/HTTP-    │
 │  replay · typestate Connection<S>              │   │  (Phase 4)     │  │  CONNECT/TLS/DNS +      │
 │  emits RunOutcome + RouteCandidate (a PLAN)    │   └────────────────┘  │  health probing        │
 │  NEVER opens a socket. NEVER links a transport.│                       │  (Phase 3)             │
 └───────────────────────────────────────────────┘                       └────────────────────────┘
   *ssk-core is a family: ssk-types, ssk-core, ssk-identity, ssk-locator,
    ssk-stitch, ssk-gates, ssk-bcik, ssk-crypto, ssk-tensor, ssk-focus,
    ssk-scheduler, ssk-audit, ssk-replay, ssk-config, ssk-privacy,
    ssk-netadmin(planner), ssk-interop, ssk-faultscan, ssk-ipc

  Legend:  existing crate   |   (NEW) missing crate that must be built
  Trust rule: everything left of ssk-netcore/ssk-capture is pure + deterministic.
              Real liveness crosses exactly one seam: RouteExecutor (netcore) and
              CaptureSource (capture), both owned and gated by ssk-daemon.
```

The critical structural correction: today `ssk-cli connect` and the daemon's `Protected` state both terminate *inside the deterministic core* (via `LocalFiberExecutor` and `AlwaysUpMockDataPlane` respectively). In the target, both must terminate *below* the core, in `ssk-netcore`, and the core must only ever hand down a plan.

---

## 2. Crate / module boundary plan

### 2.1 Existing crates → layers (with evidence)

| Layer | Crate | Role today | Evidence | Maturity (artifact / product) |
|---|---|---|---|---|
| Core (types) | `ssk-types` | Shared typed model; `ResidueRegister` (in-memory `Vec<BoundaryResidue>`) | `crates/ssk-types/src/lib.rs:730-755` | 4 / n-a |
| Core (model) | `ssk-core` | `Core`/`birefract`, `MirrorOrbit`, typestate `Connection<S>` | `crates/ssk-core/src/lib.rs:21-45`, `crates/ssk-core/src/connection.rs:121-218` | 4 / 2 |
| Core | `ssk-identity` | `derive_identity_facet` (pure) | referenced `crates/ssk-runtime/src/lib.rs:127` | 4 / n-a |
| Core | `ssk-locator` | `StaticLocatorPool`, `select_path` BFS, `PathProjectionCheck` | `crates/ssk-locator/src/lib.rs:125-227` | 4 / 1 |
| Core | `ssk-stitch` | `from_intent` candidate assembly | `crates/ssk-stitch/src/lib.rs:5-23` | 4 / n-a |
| Core | `ssk-gates` | 12-gate fail-closed vector + 9-axis PCH `Hypercube` | `crates/ssk-gates/src/lib.rs:357-417`, `crates/ssk-gates/src/pch.rs:223-262` | 4 / 3 |
| Core | `ssk-bcik` | Cryptographic crossing kernel | driven at `crates/ssk-runtime/src/lib.rs:268-283` | 4 / n-a |
| Core | `ssk-crypto` | Blake3 hashing, ed25519 vectors | `Blake3HashProvider` used at `crates/ssk-runtime/src/lib.rs:268-283` | 4 / n-a |
| Core | `ssk-tensor` | Append-only hash-chained `StitchTensor`; `DissolutionManager`; ledger backends | `crates/ssk-tensor/src/lib.rs:153-184,205-262,302-388` | 4 / 3 |
| Core | `ssk-focus` | `FocusEngine::reanalyze`, `refocuses` | `crates/ssk-runtime/src/lib.rs:302-306` | 4 / n-a |
| Core | `ssk-scheduler` | `HypertoroidalScheduler` deterministic tick + seeded jitter | `crates/ssk-scheduler/src/lib.rs:40-87` | 4 / n-a |
| Core | `ssk-audit` | `chain_trace` Blake3 hash-chained trace | `crates/ssk-runtime/src/lib.rs:136-159` | 4 / n-a |
| Core | `ssk-runtime` | Pipeline drivers `run_to_outcome` / `run_once*`; `LocalFiberExecutor`; `select_egress` | `crates/ssk-runtime/src/lib.rs:189-360,466-540` | 4 / 2 |
| Core | `ssk-replay` | `DeterministicReplayEngine` genuine re-execution | `crates/ssk-replay/src/lib.rs:26-70` | 4 / n-a |
| Core | `ssk-config` | 12-section `AppConfig`, versioning, migration, fail-closed validation | `crates/ssk-config/src/lib.rs:615-762,794-844` | 4 / n-a |
| Core | `ssk-privacy` | `LinkabilityEstimator` metric | used at `crates/ssk-gates/src/lib.rs:301` | 4 / 2 |
| Planner | `ssk-netadmin` | `PolicyEngine`, `RouteOrchestrator`, descriptor-only adapters, hash-chained ledgers | `crates/ssk-netadmin/src/{policy,route,adapter,audit,session}.rs` | 4 (planner) / 2 (adapters) |
| Interop | `ssk-interop` | Canonical CBOR, capability attestation (keyed-MAC), conformance suite | conformance CLI `crates/ssk-cli/src/main.rs:1249-1367` | 4 / 3 |
| Fault | `ssk-faultscan` | Chaos/fault taxonomy | CI `.github/workflows/ci.yml:99-105` | 4 / 3 |
| IPC | `ssk-ipc` | Unix socket transport, CBOR framing, SO_PEERCRED auth | `crates/ssk-ipc/src/{server,client,framing,auth}.rs` | 5 (local IPC) |
| Daemon | `ssk-daemon` | `sskd`: state machine, supervision, config load, **mock** data plane | `crates/ssk-daemon/src/{supervisor,state,mock_dataplane}.rs` | mixed (see §2.3) |
| CLI | `ssk-cli` | `ssk` binary: 15+ subcommands | `crates/ssk-cli/src/main.rs:37-352` | mixed |

Note the split of "policy" concepts that the target must reconcile: `ssk-config::Policy` is the **Omega gate profile** (`GateId` ordering), whereas `ssk-netadmin::PolicyEngine` is the **routing ruleset**. They are never connected today (`crates/ssk-daemon/src/main.rs:38-53` loads config then discards it; the supervisor is built with a hardcoded `reference_policy_engine`, `crates/ssk-daemon/src/supervisor.rs:112-154`).

### 2.2 Missing crates (must be created)

#### `ssk-netcore` — the real data plane (SSKΩ-7, Phase 3)

Responsibility: turn a planned `RouteCandidate` into a *real* egress. This is the only crate permitted to depend on `tokio`, `std::net`, `rustls`, DNS resolvers, or `socket2`.

- Must implement a `RouteExecutor` that consumes `ssk_netadmin::route::RouteCandidate` (`crates/ssk-netadmin/src/route.rs:14-60`) — the struct today "described as 'ready for dispatch' but nothing dispatches it" per the netadmin evidence.
- Must implement the transport behind each adapter kind that `adapter.rs` currently only *describes*: Direct (raw TCP), SOCKS5 handshake, HTTP CONNECT, TLS tunnel (SNI override), DNS override (split-horizon). The current trait has **no `connect()`** — only `adapter_id()`/`describe()` (`crates/ssk-netadmin/src/adapter.rs:37-40`), and the module doc concedes adapters are "descriptor-only ... The actual transport is the responsibility of the caller" (`crates/ssk-netadmin/src/adapter.rs:3-9`).
- Must implement health probing (liveness), which the locator "reality check" only *claims*: `locator_axes_consistent` reads three struct fields and does not even check `health == Live` (`crates/ssk-gates/src/pch.rs:195-197`).
- Must retire the reserved-but-never-produced audit outcomes by actually producing them: `AdapterUnreachable`, `KillSwitchBlocked`, `FallbackDispatched` are documented "Not yet produced by any code path until the `ssk-netcore` data-plane runtime ships (Phase 3)" (`crates/ssk-netadmin/src/audit.rs:31-42`).
- NETADMIN_SPEC already names the entry point that must live here: "A runtime `connect()` ships in **Phase 3** as `ssk-netcore::AdapterRuntime::connect`" (`docs/NETADMIN_SPEC.md:185-188`).

#### `ssk-capture` — traffic ingress (SSKΩ-9 flows, Phase 4)

Responsibility: produce real `FlowRecord`s from observed traffic so the planner has real input and the daemon can surface real recent flows.

- Today `FlowRecord` is a struct a caller hand-builds; there is no ingress that produces flows (`crates/ssk-netadmin/src/flow.rs:8-82`).
- The daemon's `ListRecentFlows` honestly returns `vec![]` with the comment "no traffic ingress exists until ssk-capture ships (Phase 4). Never fabricate flows." (`crates/ssk-daemon/src/supervisor.rs:397-401`).

#### `ssk-desktop` — optional GUI (P2)

Responsibility: a Tauri dashboard over the *same* IPC surface `ssk-cli` uses. It must hold no privileged logic; it is a view over `GetStatus`/`ActivateProfile`/`Deactivate`/`ListProfiles`.

- No GUI/Tauri/updater exists: `docs/DESKTOP_CLIENT_ARCHITECTURE.md:201` states "no Tauri, HTTP endpoints, daemon, or updater exist."
- This crate is genuinely optional for the network capability; SSKΩ-7 does not require it.

### 2.3 What is real vs mocked/hardcoded in the daemon today

Real (keep): Unix-socket IPC transport driven cross-process by the actual `sskd` binary (`crates/ssk-daemon/tests/round_trip.rs:28,46`); CBOR framing with a 16 MiB cap (`crates/ssk-ipc/src/framing.rs:15,51-57`); same-user peer auth (`crates/ssk-ipc/src/auth.rs:30-46`); the state machine + broadcast event bus (`crates/ssk-daemon/src/state.rs:10-51`); the supervised-failure watchdog → fail-closed/degraded (`crates/ssk-daemon/src/supervisor.rs:87-109`).

Mocked / hardcoded (must be replaced by `ssk-netcore`):

- Data plane is a trait with two constant stubs. `AlwaysUpMockDataPlane::route_available` returns `true` unconditionally (`crates/ssk-daemon/src/mock_dataplane.rs:17-21`); it is wired into the production binary (`crates/ssk-daemon/src/main.rs:53`), so `sskd` reaches `Protected` for any profile id via a hardcoded `true` (`crates/ssk-daemon/src/supervisor.rs:263-268`). The module doc admits it "stands in for `ssk-netcore::RouteExecutor` (Phase 3)" (`crates/ssk-daemon/src/mock_dataplane.rs:3-7`).
- `GetStatus` hardcodes `dns_protected: false` (`crates/ssk-daemon/src/supervisor.rs:251`), `kill_switch: false` (`:252`), and adapter health = "unknown (ssk-netcore not yet integrated)" (`:249`).
- `ListProfiles` returns a single hardcoded reference profile (`crates/ssk-daemon/src/supervisor.rs:325-332`).
- The daemon **never writes** its audit ledger: every reference is `.audit.entries()`/`.audit.verify()` (`crates/ssk-daemon/src/supervisor.rs:240,404,419,422`), no `.record()` call exists, so `VerifyAuditChain` verifies an empty chain and the "audit verifies" assertions are vacuous (`crates/ssk-daemon/tests/round_trip.rs:106`).

---

## 3. Trait / interface boundaries (the seams)

Three seams already exist in honest, dependency-inverted form. The completion work is to implement real collaborators *behind* them without changing the core.

### 3.1 Seam 1 — `FiberExecutor` (core echo → real egress)

The core already isolates network execution behind a trait:

- `FiberExecutor` is declared as an abstraction boundary at `crates/ssk-runtime/src/lib.rs:179-181`; its doc states a real network implementation "is exclusively `ssk-netcore`'s (Desktop track's) job and never this crate's" and is "out of scope here (Section X)" (`crates/ssk-runtime/src/lib.rs:169-178`).
- The only impl today is `LocalFiberExecutor` (`crates/ssk-runtime/src/lib.rs:189-213`), whose `payload_digest` is a content hash of the stitch's own fields (`:195-204`) — content-addressed precisely so determinism tests reproduce bit-for-bit (`crates/ssk-runtime/src/lib.rs:922-953`).

Target: `ssk-netcore` provides a `NetFiberExecutor: FiberExecutor` that performs real egress and returns a `Response` sourced from an actual peer. Because it is non-deterministic, it must live *outside* the replay/determinism test path — those tests keep `LocalFiberExecutor` (`crates/ssk-runtime/tests/conformance.rs:60,85,116,127`), and a *new* `ssk-conformance` network test drives `NetFiberExecutor` against a hermetic loopback endpoint.

### 3.2 Seam 2 — `MockDataPlane` → real `RouteExecutor` (daemon)

- The daemon's data plane is the `DataPlane` trait behind `AlwaysUpMockDataPlane`/`AlwaysDownMockDataPlane` (`crates/ssk-daemon/src/mock_dataplane.rs:17-31`), wired at `crates/ssk-daemon/src/main.rs:53`.
- Target: replace the mock with an `ssk-netcore`-backed executor that (a) consults `RouteOrchestrator::plan` output, (b) opens a real adapter transport, (c) reports true `dns_protected`/`kill_switch`, and (d) drives `Protected`/`FailClosed` from *actual* route availability rather than a constant `true`.

### 3.3 Seam 3 — descriptor → transport (netadmin adapter)

- `DataPlaneAdapter` today has exactly two methods, `adapter_id()` and `describe()` (`crates/ssk-netadmin/src/adapter.rs:37-40`); `DirectAdapter::describe()` returns `{ kind: Direct, address: "", port: 0 }` (`crates/ssk-netadmin/src/adapter.rs:63-71`) — a label with no socket behind it.
- Target: introduce a transport trait (owned by `ssk-netcore`, e.g. `AdapterRuntime::connect(&AdapterDescriptor) -> impl AsyncRead+AsyncWrite`) that consumes the descriptor the planner emits. The planner stays pure and adapter-free; only `ssk-netcore` links a socket. This preserves the honest current split (planner decides *which* adapter; executor opens it).

### 3.4 Seam 4 — path selection wiring (dead code → live)

- `HypercubePathCheck::passes` forwards to `locator_axes_consistent` and discards the phase argument (`_theta`, `crates/ssk-runtime/src/lib.rs:327-331`); `select_egress` builds the graph with `edges: Vec::new(), hyperedges: Vec::new()` (`crates/ssk-runtime/src/lib.rs:348-352`), so the real multi-hop BFS (`crates/ssk-locator/src/lib.rs:159-227`) degenerates to the zero-hop case and is reachable only from `ssk-runtime`'s own tests (`crates/ssk-runtime/src/lib.rs:833-869`).
- Target: `ssk-netcore` (or the daemon route path) populates the `LocatorGraph` with real relay edges so the tested BFS is actually exercised, and stops discarding `theta` so the "phase-consistent egress" claim becomes real.

---

## 4. Data flow — user intent → system effect

### 4.1 Today (terminates in an echo)

```
user runs `ssk connect`
  └─ connect_command (crates/ssk-cli/src/main.rs:510-581)
       args: valid_fixture/seeded/epoch ONLY — no host/port (main.rs:58-65)
       └─ run_to_outcome(sample_intent(fixture), default_pool(), LocalFiberExecutor, ...)  (main.rs:528-536)
            1. scheduler tick        (ssk-scheduler; runtime lib.rs:119-125)   REAL
            2. identity facet        (lib.rs:127)                              REAL
            3. locator select        (lib.rs:128-131, flat static pool)        REAL(flat)
            4. candidate build       (ssk-stitch; hardcodes seam/boundary=true)REAL(trivial)
            5. gate vector           (lib.rs:134)                              REAL
            6. trace chain           (lib.rs:136-159, Blake3)                  REAL
            7. fail-closed branch    (lib.rs:251-264)                          REAL
            8. BCIK crossing         (lib.rs:268-283)                          REAL crypto
            9. tensor materialize    (lib.rs:289-298, IN-MEMORY backend)       REAL(in-mem)
           10. fiber execute         (lib.rs:301, LocalFiberExecutor)          ECHO — no network
           11. concave focus         (lib.rs:302-306, over fabricated Response)REAL over fake input
       prints "connect: outcome=.. materialized=.. residues=.." (main.rs:576)
  RESULT: an abstract StitchCandidate materialized into an in-memory tensor
          discarded at process exit (main.rs:516-518). No packet leaves the box.
```

The word "connect" is a UX overclaim: the command has no destination argument and opens no socket. `LocalFiberExecutor` is honest — it "fabricates no network liveness" (`crates/ssk-runtime/src/lib.rs:176-178`).

### 4.2 Target (terminates in a real, gated egress)

```
user runs `ssk connect --to host:port` (or activates a profile via sskd)
  └─ CLI/desktop → IPC → sskd (daemon owns the data plane)
       1..9  DETERMINISTIC CORE unchanged (scheduler..gates..bcik..tensor)   REAL, pure
             gates MUST pass before any egress (fail-closed, lib.rs:251-264)
       plan  RouteOrchestrator::plan → RouteCandidate (netadmin route.rs)     REAL planner
       ───────────────────────── SEAM (RouteExecutor / NetFiberExecutor) ─────────────────────────
      10. ssk-netcore executes the plan:
            resolve adapter → open real transport (TCP/SOCKS5/HTTP CONNECT/TLS/DNS)
            health-probe; on failure → AdapterUnreachable (audit.rs:31-42, now produced)
      11. focus reanalyzes the REAL peer Response (not an echo)
       report: real dns_protected/kill_switch; ListRecentFlows fed by ssk-capture
       persist: audit.record(...) on every decision (non-vacuous verify)
  RESULT: real traffic routed or fail-closed-blocked; every decision hash-chained.
```

Invariant preserved end-to-end: **no materialization/egress without a passing gate.** This is enforced two ways today and must remain so — at runtime (`crates/ssk-runtime/src/lib.rs:251-264`) and at compile time via the typestate, where `materialize` exists only on `Connection<GatePassed>` and `gate` produces `GatePassed` only on `Pass` (`crates/ssk-core/src/connection.rs:186-217`, verified by `a_rejecting_gate_yields_no_gatepassed_connection`, `crates/ssk-core/src/connection.rs:354-361`).

---

## 5. Error flow — adapter failure → user diagnosis

### 5.1 Today

Error handling is real for the *decision core* and for *IPC*, but there is no adapter failure because there is no adapter execution:

- Gate failure → `HoldRefine` / `DissolveRejectQuarantine` with typed residues, never a silent drop (`crates/ssk-runtime/src/lib.rs:252-262`); open BCIK seam → `DissolveRejectQuarantine` carrying the residue (`:277-282`); tensor failure → `Err(RuntimeError)` (`:296-298`).
- IPC-connect failure (daemon absent) → `IpcError("Runtime","IPC_CONNECT_FAILED", ...)` with next step "Is `sskd` running? Start the daemon and retry." (`crates/ssk-ipc/src/client.rs:16-24`), mapped to CLI exit code 12 (`crates/ssk-cli/src/main.rs:194-206,237-253`).
- Planner fail-closed → `PolicyAction::FailClosed` when no rule matches (`crates/ssk-netadmin/src/policy.rs:138-157`); `RouteKind::Denied` on `FailClosed`/`Deny`/unknown adapter (`crates/ssk-netadmin/src/route.rs:127-180`). But "fail-closed here has no enforcement teeth at the network layer — there is no live egress to close" (netadmin evidence).

Caveat to fix: in the gate priority ladder a soft Hold/Refine outranks a hard Reject (`crates/ssk-gates/src/lib.rs:401-406`), which can mask a rejection's residue in the surfaced report (never opening the gate, but under-reporting the reason). No test exercises the mixed Hold+Reject case.

### 5.2 Target

```
ssk-netcore adapter fails to connect / TLS handshake fails / DNS blocked
  └─ produce AuditOutcome::AdapterUnreachable (audit.rs:31-42, now live)
       → daemon transitions to FailClosed, clears active profile (supervisor.rs:269-275)
       → kill-switch armed; Deactivate refuses unless release_kill_switch (supervisor.rs:297-309)
       → GetStatus reports kill_switch=true (currently hardcoded false, supervisor.rs:252)
       → event StateChanged emitted on the broadcast bus (state.rs:31-39)
  └─ CLI/desktop surfaces: clear class + next-step + non-zero exit (main.rs:194-206)
  └─ audit.record(AdapterUnreachable) → hash-chained, later verifiable (non-vacuous)
```

Requirement: an adapter failure must never fail *open*. Because the current kill-switch guard talks about `FailClosed` while the status field `kill_switch` is a constant `false` (`crates/ssk-daemon/src/supervisor.rs:252`), the reported flag and the actual guard are disconnected today; the target must make the surfaced flag reflect the real guard.

---

## 6. Persistence / audit flow

### 6.1 Today (real in-memory chain; not durable in any product surface)

- `StitchTensor::apply_sorted` is append-only and hash-chained: it sorts by `(epoch, StitchId)`, appends, and advances `self.head` per entry with `prev_hash`→`entry_hash` (Blake3) (`crates/ssk-tensor/src/lib.rs:153-184`).
- A working file backend exists — `GenericFileLedgerBackend` serializes via `serde_json` (`crates/ssk-tensor/src/lib.rs:302-348`) — but **every production/CLI/runtime `StitchTensor` uses an in-memory backend**: CLI connect (`crates/ssk-cli/src/main.rs:516-518`), runtime/conformance (`crates/ssk-runtime/src/lib.rs:769`, `crates/ssk-runtime/tests/conformance.rs:38`). The only file-backed stitch exercise is a toy test (`crates/ssk-tensor/src/lib.rs:585`).
- **Verification is asymmetric**: `verify()`/`verify_chain` exist only for the older `TensorEntry` ledger (`crates/ssk-tensor/src/lib.rs:44-48,373-388`); the `StitchTensorEntry` `StorageBackend` path has `get`/`iter`/`head` but **no `verify()`** (`crates/ssk-tensor/src/lib.rs:63-80`).
- **TTL dissolution is library-only**: `DissolutionManager::{is_expired,sweep,finalize_expired}` are real (`crates/ssk-tensor/src/lib.rs:205-262`) but have zero production callers (identifiers appear only in defs, the `#[cfg(test)]` block `:498-541`, and docs). Finalized residues land in an in-memory `ResidueRegister` (`crates/ssk-types/src/lib.rs:730-755`) with no persistence and no observer. Despite this, `docs/OMEGA_CORE_CONFORMANCE_SPEC.md:258` marks SSKΩ-9 "✅ met" citing these functions — an overclaim, because a tested-in-isolation function is credited as an operational capability.
- **The daemon never records its audit ledger** (§2.3), so `VerifyAuditChain` verifies an empty chain.

### 6.2 Target

```
every decision (gate result, route plan, adapter connect/fail, dissolution) →
  ssk-netadmin AuditLedger::record(...) (audit.rs:143, real hash-chain, currently unused by daemon)
  └─ persisted via GenericFileLedgerBackend (tensor lib.rs:302-348)
  └─ StitchTensorEntry gains a StorageBackend::verify() (new; parity with TensorEntry verify)
  └─ daemon calls .record() on activate/deactivate/route decisions
       → audit_head becomes Some(..) (today always None, supervisor.rs:239-243)
       → VerifyAuditChain checks a REAL non-empty chain (round_trip.rs:106 becomes non-vacuous)
  DissolutionManager::sweep driven by a real epoch tick (daemon/scheduler)
  └─ finalize_expired routes residues into the persisted, chained ledger (not the ephemeral register)
  └─ a diagnostic surface (IPC endpoint / CLI subcommand) lets a user observe swept dissolutions
```

Also fix the in-code overclaim: `finalize_expired`'s doc comment calls a non-persisted, non-chained in-memory residue "hash-chained" and "auditable" (`crates/ssk-tensor/src/lib.rs:232-234`); either make it true (route into the ledger) or correct the comment.

---

## 7. Explicit lists

### 7.1 What MUST stay in core (deterministic, adapter-free, no I/O)

Everything here must remain pure and reproducible; none may link a socket, DNS resolver, or TLS stack.

- `HypertoroidalScheduler` deterministic tick + seeded jitter — no `SystemTime`/`thread_rng` in path (`crates/ssk-scheduler/src/lib.rs:40-87`; mode selected from `DeterminismContext`, `crates/ssk-runtime/src/lib.rs:114-124`).
- The decision pipeline stages 1–9 and 11 of `run_to_outcome` (`crates/ssk-runtime/src/lib.rs:230-314`): identity, locator model, stitch, 12 gates, BCIK crossing, tensor materialization, focus.
- The 12-gate fail-closed vector and 9-axis PCH `Hypercube` (`crates/ssk-gates/src/lib.rs:357-417`, `crates/ssk-gates/src/pch.rs:223-262`).
- Typestate `Connection<S>` with compile-time fail-closed materialization (`crates/ssk-core/src/connection.rs:121-218`).
- Replay re-execution engine (`crates/ssk-replay/src/lib.rs:26-70`) and the Section-W model-property tests (`crates/ssk-runtime/tests/conformance.rs:42-132`) — kept on `LocalFiberExecutor` deliberately so replay stays bit-for-bit reproducible.
- Config schema/validation/migration (`crates/ssk-config/src/lib.rs:615-762,794-844`).
- The `ssk-netadmin` *planner* logic: `PolicyEngine`, `RouteOrchestrator`, attestation, ledgers (pure decision + crypto, no transport).

### 7.2 What MUST move out of core (real liveness → netcore/daemon)

- `LocalFiberExecutor`'s *role* as the terminal stage: the real executor must move to `ssk-netcore` behind `FiberExecutor` (`crates/ssk-runtime/src/lib.rs:179-181`). Keep `LocalFiberExecutor` for tests; do not let a network executor into the deterministic path.
- The daemon's data plane: replace `AlwaysUpMockDataPlane` (`crates/ssk-daemon/src/mock_dataplane.rs:17-21`, wired `crates/ssk-daemon/src/main.rs:53`) with an `ssk-netcore`-backed `RouteExecutor`.
- Adapter *transport*: the socket/handshake/TLS/DNS code implied by `DirectAdapter`/`Socks5Adapter`/etc. must live in `ssk-netcore`, consuming the descriptors the planner emits (`crates/ssk-netadmin/src/adapter.rs:37-71`). The descriptor builders stay in `ssk-netadmin`; only execution moves.
- Traffic ingress: `FlowRecord` production moves to `ssk-capture`; the daemon stops returning `vec![]` for `ListRecentFlows` (`crates/ssk-daemon/src/supervisor.rs:397-401`).
- Real `dns_protected`/`kill_switch`/adapter-health reporting moves from hardcoded constants (`crates/ssk-daemon/src/supervisor.rs:249-252`) to values sourced from `ssk-netcore`.

### 7.3 What is NEWLY MISSING (does not exist anywhere in the tree)

- **`ssk-netcore`** — real egress: `RouteExecutor`/`AdapterRuntime::connect` for Direct/SOCKS5/HTTP-CONNECT/TLS/DNS + health probing (absent; `docs/NETADMIN_SPEC.md:185-188`; `ls crates/ssk-netcore` → none). This is the crate SSKΩ-7 defers to (`docs/OMEGA_CORE_CONFORMANCE_SPEC.md:256`).
- **`ssk-capture`** — traffic ingress producing `FlowRecord`s (absent; `crates/ssk-daemon/src/supervisor.rs:397-401`).
- **`ssk-desktop`** — Tauri dashboard over IPC (absent; `docs/DESKTOP_CLIENT_ARCHITECTURE.md:201`). Optional for the network capability.
- **A stitch-chain `verify()`** for `StitchTensorEntry` (absent; parity gap vs `TensorEntry`, `crates/ssk-tensor/src/lib.rs:63-80`).
- **Config → runtime wiring**: threading the validated `AppConfig` into `Supervisor`/`ssk-netadmin` so it replaces `reference_policy_engine` (config is parsed then discarded today, `crates/ssk-daemon/src/main.rs:38-53`).
- **A real end-to-end network conformance test**: nothing in the tree drives TCP/UDP/TLS/DNS. Every test collaborator is `LocalFiberExecutor` or `MockDataPlane` (`crates/ssk-runtime/tests/conformance.rs:60,85,116,127`; `crates/ssk-daemon/tests/*` use `AlwaysUpMockDataPlane`). `ssk-conformance` (or an added test layer) must assert a real effect against a hermetic loopback endpoint.
- **Service packaging + lifecycle**: no systemd/launchd units exist; the daemon traps only SIGINT, not SIGTERM, leaving a stale `sskd.lock` on service kill (`crates/ssk-daemon/src/main.rs:22-36,60,71`); no cross-restart state persistence (`crates/ssk-daemon/src/supervisor.rs:45-53`); the release workflow ships a *source* tarball, not the built binaries (`.github/workflows/release.yml:19-20` vs the claim at `README.md:381`).
- **`ssk-core` no_std fix**: add `use alloc::vec::Vec;` (and `extern crate alloc;` if needed) at `crates/ssk-core/src/connection.rs:55,78,87` so the advertised, CI-claimed `no_std` build (`README.md:102`) actually compiles.

---

## 8. Doc-vs-code reconciliation (quote and contrast)

| Doc claim | Where | Code reality |
|---|---|---|
| "Production-oriented, pure Rust runtime" | `README.md:3` | "not a network runtime ... the entire live data plane, daemon, IPC, OS-integration, persistence, and signing stack must be built new" (`docs/DESKTOP_CLIENT_ARCHITECTURE.md:33-38,114-118`). |
| "traffic routing without third-party proxy software" | `README.md:39`, `docs/NETADMIN_SPEC.md:5-8` | Routes are planned, never executed; `RouteOrchestrator::plan()` returns a `RouteCandidate` and stops (`docs/DESKTOP_CLIENT_ARCHITECTURE.md:54-56`); `ssk-netcore` absent. |
| "DirectAdapter → Raw TCP" | `README.md:283-292` | `DataPlaneAdapter` has no `connect()`; only `adapter_id()`/`describe()` (`crates/ssk-netadmin/src/adapter.rs:37-40`); "descriptor-only" (`:3-9`). |
| "cryptographically-audited" / "signed capability attestation" | `README.md:39,116,389` | Attestation defaults to a symmetric Blake3 keyed-MAC, not asymmetric signing (`crates/ssk-netadmin/src/attestation.rs:6-10`; `docs/DESKTOP_CLIENT_ARCHITECTURE.md:108-110,200`). The daemon also never writes the audit chain (§2.3). |
| "SSKΩ-0 through SSKΩ-9 are all met" | `docs/OMEGA_CORE_CONFORMANCE_SPEC.md:39` | Contradicted by its own SSKΩ-7 ⚠️ row requiring real egress (`:256`). |
| "SSKΩ-9 ✅ met" (production-hardened; TTL sweeps) | `docs/OMEGA_CORE_CONFORMANCE_SPEC.md:258` | TTL sweep functions have zero callers; config discarded; audit never written; release ships source not binaries — a library-only capability graded as operational. |
| `ssk-core` "no_std-friendly and verified in CI" | `README.md:102,342-343,371` | `cargo check -p ssk-core --no-default-features` fails (E0425/E0433) at `crates/ssk-core/src/connection.rs:55,78,87`. |

Where the code is honest, it deserves credit: the daemon's live status does not overclaim (`dns_protected=false`, empty flows, "ssk-netcore not yet integrated"), and `docs/DESKTOP_CLIENT_ARCHITECTURE.md` is itself an internal audit whose Section B.6 is titled "Doc-vs-code discrepancies to correct." The overclaims live in `README.md` / `docs/NETADMIN_SPEC.md` / `docs/COMPLETION_CHECKLIST.md` marketing prose, not in the running daemon.

---

## 9. Maturity ladder — corrected per rung

| Rung | Definition (spec) | Corrected status | Basis |
|---|---|---|---|
| SSKΩ-0 | Typed model compiles | **PASS (default) / broken no_std** | builds default; `--no-default-features` fails (`crates/ssk-core/src/connection.rs:55,78,87`) |
| SSKΩ-1 | Deterministic core + scheduler | **PASS (core artifact)** | `crates/ssk-scheduler/src/lib.rs:40-87`; `crates/ssk-runtime/src/lib.rs:922-953` |
| SSKΩ-2 | Mirror-facet orbit + locator reality checks | **PARTIAL** | orientation is a placeholder (`crates/ssk-core/src/lib.rs:87-88`); "reality check" is a 3-field predicate, no liveness (`crates/ssk-gates/src/pch.rs:195-197`) |
| SSKΩ-3 | BCIK candidate pipeline carries seam/boundary/gate/trace/replay | **PASS (core artifact)** | `crates/ssk-runtime/src/lib.rs:268-283,136-159`; flags hardcoded true upstream (`crates/ssk-stitch/src/lib.rs:17-20`) |
| SSKΩ-4 | 12 gates fail-closed + PCH | **PASS with caveats** | `crates/ssk-gates/src/lib.rs:381-417`; Protocol axis always-pass (`crates/ssk-gates/src/pch.rs:139-144`); Hold-masks-Reject (`crates/ssk-gates/src/lib.rs:401-406`) |
| SSKΩ-5 | Persistent tensor + audit, verifiable | **PARTIAL** | append/chain in-memory only; no `StitchTensorEntry` verify (`crates/ssk-tensor/src/lib.rs:63-80`); daemon audit never written (§2.3) |
| SSKΩ-6 | Concave focus + replay | **PASS (core artifact)** | `crates/ssk-replay/src/lib.rs:55`; focus over echoed Response |
| SSKΩ-7 | Real egress adapters + health probing | **FAIL** | self-graded ⚠️ (`docs/OMEGA_CORE_CONFORMANCE_SPEC.md:256`); `ssk-netcore` absent; adapters descriptor-only |
| SSKΩ-8 | Simulation + conformance testbed | **PASS (model testbed)** | all collaborators are the abstract model / test-doubles |
| SSKΩ-9 | Production-hardened runtime | **PARTIAL** | TTL sweep uncalled; config discarded; audit vacuous; release ships source |

Honest ceiling today: **level 4 as a decision/audit/planning core artifact; level 2 as a network/privacy product capability.** The path to level 5 is entirely gated on SSKΩ-7 — building `ssk-netcore` behind the existing `FiberExecutor`/data-plane seams, wiring config through, making persistence durable and verifiable, and adding a real end-to-end network test. The core does not need to change to get there; it needs a real collaborator behind a seam it already, honestly, defined.