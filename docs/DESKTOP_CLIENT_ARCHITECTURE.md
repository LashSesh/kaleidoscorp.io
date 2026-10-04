# Kaleidoscorp Desktop Privacy Client — Formal Implementation Architecture

> Implementation update (2026-09-24): a modular UI and a Windows Tauri host now
> read daemon status. [Current desktop/backend boundary](DESKTOP_BACKEND_CONNECTION.md)
> supersedes the older GUI availability findings below; broad control and verified
> protection displays remain future work.

> Status: **Architecture specification** (no code in this document).
> Scope: Turn the existing ScorpioSync-Kaleidoscorp Ω *decision-modeling core* into a
> product-grade, cross-platform desktop privacy client whose runtime can really route,
> block, audit, and live-stream network flows — and which a Tauri dashboard GUI can sit on
> top of without any illusion about non-existent networking.
>
> Every statement about the **current** state of the repository is traced to a concrete file
> and, where useful, a line number. Every statement about the **target** state is framed as an
> implementable, testable Rust component. The two are never mixed.

---

## Legend — implementation status classification

Throughout this document, current-state findings carry one of five tags:

| Tag | Meaning |
|-----|---------|
| **[1] Implemented** | Real, exercised by tests, does the work it claims. |
| **[2] Partial** | Real logic, but incomplete for product use (e.g. in-memory only, decoupled, or descriptor-only). |
| **[3] Doc/Roadmap-only** | Described in docs but not present in code, or code contradicts the doc. |
| **[4] Derivable-missing** | Logically implied by the system, not yet present. |
| **[5] Mandatory-for-product** | Must exist before this can ship as a desktop privacy client. |

---

## A. Executive Architecture Diagnosis

### A.1 What the repository *actually is today*

The repository is a **synchronous, deterministic, `no_std`-friendly decision-and-audit
modeling core with a hardened CLI**. It classifies flows, evaluates policy, *plans* routes,
computes MAC-based attestations, and maintains hash-chained ledgers — all as in-memory data
structures. It is well-engineered and well-tested for what it is.

It is **not** a network runtime. Across the entire 21-crate workspace there is:

- **Zero `async fn`** — verified by `grep -rn "async fn" crates/` → 0 hits.
- **Zero `tokio`/async-std/mio/hyper/rustls/socks** — no crate manifest depends on any of them
  (`crates/*/Cargo.toml`; workspace deps in `Cargo.toml:32-51` are all synchronous).
- **Zero sockets** — no `TcpStream`, `TcpListener`, `UdpSocket`, `UnixListener` anywhere. The
  only textual hit for "tokio/async/socket" in `crates/**/*.rs` is the disclaiming comment at
  `crates/ssk-netadmin/src/adapter.rs:9` ("avoids pulling in async/tokio dependencies").

Concretely, the "network administration layer" `ssk-netadmin`:

- **Adapters `describe()` but never `connect()`.** The `DataPlaneAdapter` trait
  (`crates/ssk-netadmin/src/adapter.rs:37-40`) has exactly two methods: `adapter_id()` and
  `describe()`. The module header (`adapter.rs:5-9`) states adapters are
  *"descriptor-only: they define how a connection should be set up, not the networking
  implementation itself. The actual transport is the responsibility of the caller."*
- **Routes are *planned*, never *executed*.** `RouteOrchestrator::plan()`
  (`crates/ssk-netadmin/src/route.rs:117-128`) returns a `RouteCandidate` struct and stops.
  `RouteKind::Fallback` is defined (`route.rs:55-59`) but never even produced by the planner.
- **Policy returns enums, enforces nothing on a wire.** `PolicyEngine::evaluate()`
  (`crates/ssk-netadmin/src/policy.rs:138-157`) returns a `PolicyDecision`; `RolloutMode::is_enforcing()`
  (`crates/ssk-netadmin/src/control.rs:28-30`) returns a `bool` that a *caller* would have to honor.
- **Flows are hand-built, not captured.** `FlowRecord`/`FlowDescriptor` constructors
  (`crates/ssk-netadmin/src/flow.rs:44-81`) are filled in by callers; there is no packet capture,
  pcap, eBPF, or listener.
- **Ledgers were in-memory only** at the time of this diagnosis. `AuditLedger` and `SessionLedger`
  had real BLAKE3 hash-chaining and `verify()` but no disk persistence.
  **Fixed in Phase 1:** both are now generic over an `ssk_tensor::GenericLedgerBackend<E>` storage
  backend, with a `::persisted(path)` constructor that survives a process restart (see M-Phase 1).

### A.2 What it *can* do (genuinely)

- Deterministic single-pass runtime pipeline with replay verification and a replay manifest
  (`crates/ssk-runtime/src/lib.rs:78-180`; proven by `crates/ssk-runtime/tests/replay_vectors.rs`
  and `determinism_regression.rs`).
- A real fail-closed 12-gate decision vector (`crates/ssk-gates/src/lib.rs`) that short-circuits on
  the first `Reject`/`Quarantine`.
- Real content-addressed, hash-chained tensor ledger with **disk persistence** via
  `FileLedgerBackend` and integrity `verify_chain` (`crates/ssk-tensor/src/lib.rs:52-119`).
- Canonical CBOR encoding + strict non-canonical rejection, SemVer/capability interop negotiation
  (`crates/ssk-interop/src/lib.rs`; proven by `crates/ssk-interop/tests/golden_vectors.rs`).
- Versioned config (v2) with legacy-v1 migration and fail-closed validation
  (`crates/ssk-config/src/lib.rs:6, 160-235`).
- A UX-contract CLI (`--json`, machine error codes/classes/exit codes) — the `ssk` binary
  (`crates/ssk-cli`), proven by `crates/ssk-cli/tests/ux_snapshots.rs`.
- Real, in-memory hash-chained policy/route/audit pipeline for **modeling** decisions
  (`crates/ssk-netadmin/tests/netadmin_integration.rs`).

### A.3 What is *missing* for product readiness (the gap)

Everything between "we decided what should happen to this flow" and "bytes actually moved (or
did not move) on the wire", plus everything a desktop product needs around it:

1. A **data plane** that actually opens sockets and proxies traffic (SOCKS5 / HTTP CONNECT /
   TLS tunnel / Direct) and really overrides DNS. *(Currently [2]/[3] descriptor-only.)*
2. A **route executor** that runs `RouteKind` including multi-hop and fallback. *([4] missing.)*
3. **OS traffic ingress** (system proxy → TUN → per-app) so real applications' traffic enters
   the pipeline. *([4]/[5] missing.)*
4. A **local daemon / background service** that is the actual product runtime. *([3] roadmap.)*
5. A **local IPC/API** (Unix socket / named pipe / loopback HTTP) with local-only auth so a GUI
   or CLI can drive the daemon. *([3] roadmap.)*
6. A **live event stream** and a **live product state machine**. *([4] missing.)*
7. **Persistent, versioned product config** (profiles, adapters, chains, app rules, DNS rules,
   kill-switch, update channel, GUI prefs) **with a save path** — the current config crate is
   read-only and has no product-profile model. *([2]/[4].)*
8. **Audit persistence** to disk. **Done (Phase 1):** the netadmin ledgers now delegate to a
   generalized `ssk-tensor` storage backend via `::persisted(path)`. *([1] done.)*
9. **Real asymmetric signing** for attestation, signed config changes, and update verification.
   **Done (Phase 1):** `ssk-crypto`'s `crypto` feature now implements `Ed25519KeyPair`/`Ed25519Verifier`
   (`SignatureProvider`) and `ChaCha20Poly1305Provider` (`AeadProvider`). Attestation itself
   (`ssk-netadmin::AttestationBinder`, `ssk-interop::Blake3KeyedVerifier`) still *defaults* to the
   symmetric BLAKE3 keyed-MAC — wiring the new ed25519 impls into `AttestationBinder` as an
   alternative scheme is not yet done. *([1] crypto primitives done / [4] attestation wiring remains.)*
10. A **secret store**, a **permission model**, a **secure updater with rollback**, and a
    **Tauri bridge** over the IPC. *([3]/[4]/[5].)*

### A.4 One-line verdict

> A sound, well-tested **decision/audit modeling engine** exists. The entire **live data plane,
> daemon, IPC, OS-integration, persistence, and signing** stack must be built new *around* it —
> additively, reusing the existing crates as the control-plane brain, discarding nothing.

---

## B. Current Implementation Inventory

Status tags per the legend. Evidence is file:line.

### B.1 Core / control-plane crates

| Crate | LOC | Status | What is real | Evidence |
|-------|-----|--------|--------------|----------|
| `ssk-types` | 412 | **[1]** | Domain primitives, 12 `GateId`, canonical CBOR (`ciborium`), `digest_of` (BLAKE3 + SHA-256). `CryptoAlgSet` default advertises `ed25519/x25519/chacha20poly1305` as **string labels only** — no impls. | `crates/ssk-types/src/lib.rs:292-300, 370-388` |
| `ssk-gates` | 281 | **[1]** | 12 gates, each with concrete reject conditions; `GateVector::evaluate` fails closed (first Reject/Quarantine short-circuits). | `crates/ssk-gates/src/lib.rs` |
| `ssk-tensor` | 159 | **[1]** | Append-only BLAKE3 hash chain; `MemoryBackend` (RwLock) + `FileLedgerBackend` (serde_json persistence); `verify_chain` detects gaps/mutations. **This is the reusable persistence primitive for audit.** | `crates/ssk-tensor/src/lib.rs:52-119` |
| `ssk-scheduler` | 67 | **[1]** | Deterministic phase-tick; proptest reproducibility. | `crates/ssk-scheduler/src/lib.rs` |
| `ssk-interop` | 716 | **[1]** logic / **[2]** security | Canonical CBOR, strict non-canonical rejection, SemVer + capability negotiation, 7-profile conformance suite, `Blake3KeyedVerifier` MAC. MAC is symmetric; comment: *"Not for production use; replace with a real asymmetric scheme"*. | `crates/ssk-interop/src/lib.rs:46-72, 286-557` |
| `ssk-config` | 351 | **[1]** read / **[4]** write | v2 model, YAML+TOML input, legacy-v1 migration, fail-closed validate, JSON-Schema. **No save/write-to-disk path; no product profile/adapter/chain model.** | `crates/ssk-config/src/lib.rs:6, 160-315` |
| `ssk-runtime` | 425 | **[1]** pipeline / **[3]** as "runtime" | Single-shot deterministic pipeline, replay manifest, `RuntimeMetrics`, `RuntimeEvent` (constructs a struct, publishes nowhere). No loop, no service, no async. | `crates/ssk-runtime/src/lib.rs:78-219` |
| `ssk-core` | 61 | **[1]** minimal | `Orbit::derive/recover` facet helper + sealed-trait pattern. Domain types actually live in `ssk-types`. | `crates/ssk-core/src/lib.rs:11-36` |
| `ssk-cli` | 1616 | **[1]** UX | `ssk` binary; commands below. UX contract (`--json`, error classes, exit codes). | `crates/ssk-cli/src/main.rs` |

### B.2 `ssk-netadmin` (the control-plane brain — the reusable decision core)

| Module | Status | What it is | Evidence |
|--------|--------|-----------|----------|
| `flow` | **[1]** model / **[4]** ingest | `FlowDescriptor`/`FlowRecord`, `ProtocolKind`, `RiskLevel`. Hand-built; no capture. | `crates/ssk-netadmin/src/flow.rs:9-81` |
| `policy` | **[1]** eval / **[2]** enforce | Ordered rule engine, 6 actions, implicit fail-closed on no-match. Returns enums. | `crates/ssk-netadmin/src/policy.rs:15-157` |
| `route` | **[1]** plan / **[4]** execute | `RouteOrchestrator::plan` → `RouteCandidate`. `Fallback` variant defined but never produced. No executor. Unknown adapter → `Err(UnknownAdapter)` (fail-closed). | `crates/ssk-netadmin/src/route.rs:48-184` |
| `adapter` | **[2]** descriptor-only | 5 adapters (`Direct/Socks5/HttpConnect/TlsTunnel/DnsOverride`); only `describe()`. No `connect()`. | `crates/ssk-netadmin/src/adapter.rs:14-270` |
| `attestation` | **[1]** crypto / **[2]** as "signing" | Real BLAKE3 keyed-MAC sign/verify; symmetric, not asymmetric. | `crates/ssk-netadmin/src/attestation.rs:67-113` |
| `session` | **[1]** chain, **[1]** persistence | Real BLAKE3 hash chain + `verify`. **Phase 1:** generic over `ssk_tensor::GenericLedgerBackend<E>`; `SessionLedger::persisted(path)` survives a process restart. | `crates/ssk-netadmin/src/session.rs` |
| `audit` | **[1]** chain, **[1]** persistence | `AuditOutcome`, `ForensicEntry`, `AuditLedger` hash chain + `verify`. **Phase 1:** `AuditLedger::persisted(path)` gives real, tested disk persistence via the generalized `ssk-tensor` backend. | `crates/ssk-netadmin/src/audit.rs` |
| `control` | **[1]** model | `RolloutMode` (Strict/Shadow/Audit/Emergency), `OperatorProfile`, `TenantContext`, adapter/risk checks over `Vec`s. | `crates/ssk-netadmin/src/control.rs:12-169` |
| `error` | **[1]** | `NetAdminError` — 9 logical variants, **no `std::io::Error` variant** (confirms no I/O). | `crates/ssk-netadmin/src/error.rs:6-25` |

### B.3 Small crates

| Crate | Status | Note | Evidence |
|-------|--------|------|----------|
| `ssk-identity` | **[1]** trivial | Thin wrapper over `Orbit::derive/recover`. | `crates/ssk-identity/src/lib.rs` |
| `ssk-locator` | **[1]** minimal | `LocatorPool` select-first-viable. | `crates/ssk-locator/src/lib.rs` |
| `ssk-bcik` | **[1]** minimal | `cross()` → `Closed` or typed residue. | `crates/ssk-bcik/src/lib.rs` |
| `ssk-stitch` | **[2]** | `from_intent` **hardcodes** seam/boundary/replay/focus = true; only capability/signature/ttl flow through. | `crates/ssk-stitch/src/lib.rs` |
| `ssk-focus` | **[2]** stub-level | Single `refocuses()` bool. | `crates/ssk-focus/src/lib.rs` |
| `ssk-replay` | **[1]** shallow | Exact-equality diff of two runs; not independent re-exec. | `crates/ssk-replay/src/lib.rs` |
| `ssk-faultscan` | **[2]** | Real chaos harness; decoupled from real gate vector via caller closure; `LocatorUntrust` is a signature-corruption proxy. | `crates/ssk-faultscan/src/lib.rs:101-105` |
| `ssk-privacy` | **[2]** | `linkability_score = risk` (untrusted) or `risk/2` (trusted); wired into Privacy gate (threshold 50) but is a one-line heuristic, not anonymity analysis. | `crates/ssk-privacy/src/lib.rs` |
| `ssk-crypto` | **[1]** (was [3] stub) | **Phase 1:** `SignatureProvider` (`Ed25519KeyPair`/`Ed25519Verifier`) and `AeadProvider` (`ChaCha20Poly1305Provider`) now implemented behind the `crypto` feature. `KeyAgreementProvider`/`CapabilityWitnessProvider` remain unimplemented (not required yet). | `crates/ssk-crypto/src/lib.rs` |
| `ssk-audit` | **[2]** misnamed | 12-line single-record trace-hash helper; **not** a ledger. Real ledgers are in `ssk-tensor` + `ssk-netadmin`. | `crates/ssk-audit/src/lib.rs` |

### B.4 CLI command surface (`ssk` binary)

| Command | Real effect | Persistent state | Status | Evidence |
|---------|------------|------------------|--------|----------|
| `run` | Executes deterministic pipeline once; updates metrics. | `.ssk/metrics.json` | **[1]** | `main.rs:273-332, 740-800` |
| `replay-verify` | Runs pipeline twice, compares determinism. | metrics file | **[1]** | `main.rs:334-422` |
| `verify-ledger --path` | Reads JSON ledger, verifies BLAKE3 chain. | read-only | **[1]** | `main.rs:424-458` |
| `doctor [--ledger-path]` | Real env probes (clock, `/dev/urandom`, paths, permissions). | creates `.ssk/`, temp file | **[1]** | `main.rs:460-547` |
| `explain <target>` | Static lookup table. | none | **[3]** static | `main.rs:549-577, 896-969` |
| `config lint --path` | Parse + validate + migrate. | read-only | **[1]** | `main.rs:579-626` |
| `config schema` | Prints JSON-Schema. | none | **[3]** static | `main.rs:628-655` |
| `interop conformance` | In-memory policy eval; zero test key. | none | **[1]** logic | `main.rs:992-1104` |
| `chaos drill [--fault]` | Fault injection through a **stub** inline gate closure. | none | **[2]** | `main.rs:1110-1216` (stub at `:1115`) |
| `net-admin flow-inspect` | Classifies a synthetic flow. **No connection.** | none | **[3]** descriptor | `main.rs:1243-1464` |
| `net-admin route-trace` | Computes a route *descriptor*. **Never dials.** | none | **[3]** descriptor | same |
| `net-admin audit-dump` | Canned two-flow pipeline, in-memory audit chain. | none | **[2]** | same |

### B.5 Tests as capability evidence

- `crates/ssk-runtime/tests/runtime_integration.rs` — valid→`Pass`+1 tensor entry; invalid→non-Pass, no stitch, residues. **Core fail-closed proof. [1]**
- `crates/ssk-runtime/tests/{replay_vectors,determinism_regression}.rs` — deterministic replay & byte-identical outcomes across seed/epoch. **[1]**
- `crates/ssk-interop/tests/golden_vectors.rs` — canonical round-trip, strict decoder rejects non-canonical, capability mismatch, 7-profile conformance, MAC round-trip, decoder no-panic proptest. **[1]**
- `crates/ssk-netadmin/tests/netadmin_integration.rs` — full policy→route→attest→ledger pipeline, 10-entry audit `verify`. **Proves logic; opens no socket. [1] modeling / [2] product.**
- `crates/ssk-cli/tests/ux_snapshots.rs` — spawns real `ssk`, asserts JSON `status/outcome/next_steps`. **[1]**
- Root `tests/` holds only fixtures (`tests/vectors/{valid,invalid}_intent.json`).

### B.6 Doc-vs-code discrepancies to correct (product-honesty)

1. `docs/NETADMIN_SPEC.md:176-182` documents `DataPlaneAdapter::connect()` — **does not exist**; real trait has `describe()` only (`adapter.rs:37-40`).
2. `SECURITY.md:47-49` claims zero-key constructors are *"compile-time restricted to test builds"* — **false**; `Blake3KeyedVerifier::new` / `AttestationBinder::new` are unrestricted `pub` constructors (`ssk-interop/src/lib.rs:53-57`).
3. README/`COMPLETION_CHECKLIST.md` mark "signed capability attestation" and "Proxifier replacement" as done, while README/`EVOLUTION_STAGE_2_REPORT.md` list the same as future. Reality: symmetric MAC + descriptor engine → **not** signed, **not** a data plane.
4. `docs/ROADMAP_DESKTOP_GUI.md` — 100% roadmap; no Tauri, HTTP endpoints, daemon, or updater exist.

These are fixed by **Section L** (guarantees & forbidden claims) and by the implementation, not by prose alone.

---

## C. Product Target Definition

**Kaleidoscorp Client** is a compact, high-end, cross-platform **desktop privacy client** built on
the Kaleidoscorp decision core. It is adjacent to VPN clients, proxy managers, Hamachi-style
network clients, and Proxifier-style traffic-steering tools — but it is its own product: a
futuristic, dashboard-first control surface for privacy, proxy chains, routing policies,
attestation, fail-closed enforcement, and auditability.

### C.1 Product principles

1. **Dashboard-first.** The primary surface is a status dashboard: activate/deactivate, current
   protection state, chosen route/profile, warnings, and expandable detail. Flow control, policy
   inspection, audit, replay, and forensics are first-class *secondary* surfaces, not the home
   screen.
2. **The daemon is the product.** All real work (routing, blocking, DNS, capture, audit) happens
   in a background daemon. The GUI (and CLI) are thin clients over a stable local API. There is
   **no CLI-shell-scraping as a product standard**.
3. **Fail-closed by default.** If protection cannot be guaranteed, traffic is blocked, not
   silently leaked. No silent direct fallback, ever.
4. **Truth in the UI.** The GUI never displays protection that the data plane is not actually
   providing. State shown = state enforced.
5. **Auditable.** Every dangerous or state-changing action lands in a tamper-evident, persisted
   audit chain.

### C.2 Primary user journey (informs the API and state model, not a GUI design)

Activate → see live protection state → pick a profile/route → understand what is and is not
protected (routing, DNS, per-app) → receive warnings on degradation → expand into flow/policy/audit
detail on demand → deactivate cleanly (kill-switch honored throughout).

### C.3 Non-goals

- Not a general VPN concentrator or server.
- Not a bare admin dashboard.
- Not an anonymity network; **no unqualified anonymity claims** (see Section L).

---

## D. Missing Runtime Layer (full analysis)

The product needs five new layers between the existing control-plane brain and the OS/GUI. Each
is specified in detail in later sections; summarized here as the gap map.

### D.1 Local daemon / background service — **[3]→[5]**

No long-running process exists (`ssk-runtime` runs once per call). Needed: a supervised,
autostart-capable service that owns live state, config, capture, data plane, event stream, audit
persistence, kill-switch, and crash recovery. → **Section F**, crate `ssk-daemon`.

### D.2 Data plane — **[2]/[4]→[5]**

Adapters are descriptor-only; routes are planned not executed. Needed: async adapter runtimes that
really open sockets and proxy bytes, a route executor (incl. multi-hop/fallback), DNS runtime,
health checks, timeouts, retries, circuit breaker, unknown-adapter=deny, no silent direct fallback.
→ **Section G**, crate `ssk-netcore`.

### D.3 OS traffic ingress — **[4]→[5]**

Flows are hand-built. Needed: system-proxy integration (MVP), TUN interface (advanced), and per-app
control, feeding real `FlowRecord`s into the existing policy pipeline. → **Section H**, crate `ssk-capture`.

### D.4 IPC / local API — **[3]→[5]**

No IPC exists. Needed: a local transport (Unix socket / Windows named pipe / optional loopback HTTP),
local-only authentication, request/response DTOs, error mapping, and an event subscription channel,
shared verbatim by GUI and CLI. → **Sections J, F.5**, crate `ssk-ipc`.

### D.5 Persistence, secrets, signing, updates — **[2]/[3]→[5]**

Needed: persisted product config with a save path and product-profile model (`ssk-config` v3);
persisted audit chains (wire netadmin ledgers to `ssk-tensor` `FileLedgerBackend` — **done**, see B.6);
OS-keychain secret store (`ssk-secrets`); secure updater with mandatory signatures + rollback
(`ssk-updater`). Real ed25519 signing is **done**: `ssk-crypto`'s `crypto` feature now implements
`SignatureProvider`/`AeadProvider` (`Ed25519KeyPair`, `Ed25519Verifier`, `ChaCha20Poly1305Provider`) —
no separate `ssk-signing` crate was needed, since the optional `ed25519-dalek`/`chacha20poly1305`
dependencies already sat unused in `ssk-crypto`. → **Sections I, F.9, L**.

---

## E. Target Rust Workspace Architecture

All new crates are `#![forbid(unsafe_code)]` (consistent with the workspace lint at `Cargo.toml`),
except where an OS FFI boundary genuinely requires `unsafe` — there it is confined to a single
`ssk-capture` platform submodule behind a safe wrapper, with a crate-local `#![deny(unsafe_op_in_unsafe_fn)]`.

### E.1 Dependency layering (control plane → data plane → service → clients)

```
        ┌────────────────────────── clients ──────────────────────────┐
        │  ssk-tauri-bridge (GUI)          ssk-cli (retargeted)        │
        └───────────────┬──────────────────────────┬──────────────────┘
                        │  ssk-ipc (DTOs, transport, local auth, events)│
        ┌───────────────┴───────────────── service ────────────────────┐
        │                     ssk-daemon (product runtime)              │
        │  state machine · supervisor · config reload · kill-switch ·   │
        │  crash recovery · audit persistence · event bus               │
        └───┬───────────────┬───────────────┬──────────────┬───────────┘
            │               │               │              │
   ┌────────┴──────┐ ┌──────┴──────┐ ┌──────┴─────┐ ┌──────┴──────┐
   │ ssk-netcore   │ │ ssk-capture │ │ ssk-secrets│ │ ssk-updater │  (data plane + platform)
   │ adapter rt·   │ │ sys-proxy·  │ │ keychain·  │ │ signed·     │
   │ route exec·   │ │ TUN· app-   │ │ zeroize    │ │ rollback    │
   │ DNS· breaker  │ │ rules       │ └──────┬─────┘ └──────┬──────┘
   └───────┬───────┘ └──────┬──────┘        │              │
           │                │            (ed25519 via ssk-crypto's `crypto` feature — done)
           │                │                              │
   ┌───────┴────────────────┴──────────────────────────────┴─── control plane (existing, reused) ──┐
   │ ssk-netadmin (policy·route-planner·attestation·control·audit-model)                          │
   │ ssk-runtime · ssk-gates · ssk-tensor(persistence) · ssk-interop · ssk-config · ssk-types …   │
   └──────────────────────────────────────────────────────────────────────────────────────────────┘
```

Rule: **data-plane and service crates depend on the control-plane crates, never the reverse.** The
existing `no_std`-friendly crates stay `no_std`-friendly; tokio lives only in the new `std` crates.

### E.2 New crates

#### `ssk-netcore` — async data-plane runtime (**[5]**)

Responsibility: actually move (or refuse to move) bytes according to a `RouteCandidate` from the
existing planner.

Public API (illustrative signatures — types reuse `ssk-netadmin` where possible):

```rust
#[async_trait]
pub trait AdapterRuntime: Send + Sync {
    fn adapter_id(&self) -> &str;
    fn descriptor(&self) -> ssk_netadmin::adapter::AdapterDescriptor;
    /// Establish a stream to `dst` through this adapter. Never falls back to Direct.
    async fn connect(&self, dst: &Destination, deadline: Instant) -> Result<TunnelStream, NetcoreError>;
    /// Cheap liveness probe used by health checks / circuit breaker.
    async fn health_check(&self, deadline: Instant) -> Result<AdapterHealth, NetcoreError>;
}

pub struct DirectRuntime;              // real TcpStream connect
pub struct Socks5Runtime { /* host, port, auth */ }      // real RFC 1928 handshake
pub struct HttpConnectRuntime { /* proxy, auth */ }      // real CONNECT + 200 parse
pub struct TlsTunnelRuntime { /* relay, sni, mtls */ }   // real rustls client
pub struct DnsRuntime { /* resolver, mode: Udp|DoT */ }  // real resolution/override

pub struct AdapterRegistry { /* id -> Arc<dyn AdapterRuntime> */ }
pub struct RouteExecutor { registry: AdapterRegistry, policy: RetryPolicy, breaker: CircuitBreaker }

impl RouteExecutor {
    /// Execute a planned RouteKind (Direct/SingleHop/MultiHop/Fallback/Denied).
    /// `Denied` => Err(NetcoreError::Denied); unknown adapter => Err(UnknownAdapter) (fail-closed).
    async fn execute(&self, cand: &ssk_netadmin::route::RouteCandidate, dst: &Destination)
        -> Result<TunnelStream, NetcoreError>;
}
```

Guarantees: `MultiHop` chains adapters left-to-right (each hop's stream carries the next
handshake); `Fallback { primary, fallback }` tries primary, and on a *transport* failure (not a
policy `Denied`) executes fallback; **`RouteKind::Denied` and unknown adapters always error — never
Direct.** Depends on: `ssk-netadmin` (descriptors, `RouteKind`, `RouteCandidate`), `tokio`,
`rustls`, `hickory-resolver` (DNS), `ssk-secrets` (credential retrieval).

Serializable data models: `Destination`, `AdapterHealth`, `NetcoreError`, `FlowStat` (bytes,
duration, hops, outcome) — all `serde`.

#### `ssk-capture` — OS traffic ingress (**[5]**)

Responsibility: get real application traffic into the pipeline and emit real `FlowRecord`s.

```rust
#[async_trait]
pub trait IngressProvider: Send + Sync {
    async fn start(&self, sink: FlowSink) -> Result<IngressHandle, CaptureError>;
    async fn stop(&self, h: IngressHandle) -> Result<(), CaptureError>;
    fn capabilities(&self) -> IngressCapabilities;  // per-app? udp? dns-intercept?
}

pub struct SystemProxyProvider;   // MVP: set OS proxy → local listener → policy → ssk-netcore
pub struct TunProvider;           // advanced: TUN device → packet/flow assembly
pub struct AppRuleProvider;       // per-app steering (platform-specific)
```

`FlowSink` hands each accepted connection's `FlowRecord` (built from real peer/SNI/app metadata)
to the daemon, which runs it through `ssk-netadmin` policy → route plan → `ssk-netcore` execution.
Platform submodules: `platform/{windows,macos,linux}.rs`. This is where the (confined) OS FFI lives.

#### `ssk-daemon` — the product runtime (**[5]**)

Responsibility: be the always-on service. Owns the live **state machine** (Section K), supervises
`ssk-capture` + `ssk-netcore`, applies config, persists audit, runs health/breaker loops, enforces
kill-switch/fail-closed, recovers from crashes, and serves `ssk-ipc`. Binary: `ssk-daemon` (aka
`sskd`). Consumes `ssk-runtime` for the deterministic decision pipeline.

#### `ssk-ipc` — local transport + protocol + DTOs (**[5]**)

Responsibility: the single control channel shared by GUI and CLI. Unix domain socket (Linux/macOS)
/ Windows named pipe, with an optional loopback-only HTTP mode for the Tauri sidecar. Local-only
authentication (peer-credential check + per-session capability token). Defines every request/response
DTO (Section J) and the event envelope (Section K) once, so GUI and CLI never diverge. `serde` +
length-prefixed CBOR framing (reusing `ssk-interop` canonical encoding + strict decode).

#### `ssk-secrets` — secret store (**[5]**)

OS keychain backends (Windows Credential Manager, macOS Keychain, Linux Secret Service/libsecret),
in-memory `zeroize`, and redaction helpers used everywhere secrets could be logged/serialized.
Never returns a secret across IPC in plaintext except to the local, authenticated GUI on explicit,
audited request.

#### `ssk-crypto`'s `crypto` feature — real asymmetric signing (**[1] done**)

ed25519 (via `ed25519-dalek`), implemented directly inside `ssk-crypto` behind its existing
`crypto` feature rather than a separate crate — `ed25519-dalek`/`x25519-dalek`/`chacha20poly1305`
were already declared as unused optional dependencies there. `Ed25519KeyPair`/`Ed25519Verifier`
implement `SignatureProvider`; `ChaCha20Poly1305Provider` implements `AeadProvider`. Used for:
signed config changes, attestation upgrade (replacing/wrapping the symmetric MAC), and
update-artifact verification. Key generation is seed-based (`rand::random()` → `SigningKey::from_bytes`),
needing no new `rand_core`/`zeroize` workspace dependency. Keystore integration (`ssk-secrets`) is
still Phase 5 work.

#### `ssk-updater` — secure updates (**[5]**)

Channels `stable`/`beta`; **signature verification mandatory** (via `ssk-crypto`'s ed25519 impls);
atomic install; rollback to last-known-good. Realizes `docs/ROADMAP_DESKTOP_GUI.md` auto-update section.

#### `ssk-tauri-bridge` — GUI backend (**[5]**, Phase 7)

Thin `#[tauri::command]` layer that forwards to `ssk-ipc` DTOs and relays events to the webview.
No business logic, no shell-out. Ships the Tauri app.

### E.3 Extended existing crates

| Crate | Extension |
|-------|-----------|
| `ssk-netadmin` | **Done:** `AuditLedger`/`SessionLedger` are now generic over an `ssk_tensor::GenericLedgerBackend<E>` storage backend, defaulting to in-memory with an additive `::persisted(path)` constructor for real disk persistence. Remaining: a `RouteCandidate`→executable binding hook consumed by `ssk-netcore`; `AuditOutcome` variants for real transport outcomes (`AdapterUnreachable`, `KillSwitchBlocked`, `FallbackDispatched` — added as reserved/not-yet-produced). |
| `ssk-config` | New **v3** product schema (Section I): profiles, adapters, chains, app rules, DNS rules, kill-switch, attestation reqs, tenant context, audit/logging, update channel, GUI prefs. Add a **save/write + atomic-replace path** (currently read-only) and a v2→v3 migration alongside the existing v1→v2. |
| `ssk-crypto` | **Done:** real impls behind the `crypto` feature — `Ed25519KeyPair`/`Ed25519Verifier` (`SignatureProvider`), `ChaCha20Poly1305Provider` (`AeadProvider`). `KeyAgreementProvider` (x25519) and `CapabilityWitnessProvider` remain unimplemented (no current acceptance criterion needs them). |
| `ssk-cli` | Retarget `run/replay-verify/verify-ledger/doctor/net-admin/...` to talk to the daemon through `ssk-ipc`; keep an offline `--local` mode for the pure decision pipeline. |
| `ssk-runtime` | Expose the deterministic pipeline as a re-entrant, service-callable unit (borrowable by the daemon per flow), plus wire `RuntimeEvent` into the daemon event bus. |

---

## F. Daemon Specification (`ssk-daemon`)

The daemon is the product runtime; the GUI is only its visible client.

### F.1 Process model

- Single long-lived async process (tokio multi-thread runtime). One instance per machine (or per
  user, platform-dependent), guarded by a lock file + IPC-endpoint existence check.
- Internally structured as supervised tasks: `ingress` (ssk-capture), `dataplane` (ssk-netcore
  executor pool), `health` (adapter probes + circuit breaker), `ipc` (ssk-ipc server), `events`
  (broadcast bus), `persistence` (audit/state writer), `config-watch`.
- A task crash is caught by the supervisor, transitions the machine to `degraded` or `fail_closed`
  (Section K), emits an event, and attempts bounded restart with backoff.

### F.2 Start / stop behavior

- **Start:** acquire lock → load + validate config (fail-closed on invalid → `config_invalid`
  state, protection off, GUI can still connect to fix it) → open audit ledger (persisted) →
  bring up IPC → *idle in `inactive`* (do not auto-activate protection unless config says so).
- **Stop:** on signal (SIGTERM / service stop / GUI `deactivate` + shutdown), honor kill-switch
  policy: either restore direct networking (clean deactivate) or keep fail-closed until explicit
  release, per config `kill_switch.on_exit`. Flush audit, release lock, exit.

### F.3 Autostart

- Linux: systemd user/system unit (`sskd.service`) or XDG autostart for user mode.
- macOS: `launchd` LaunchDaemon (privileged capture) or LaunchAgent (user/system-proxy MVP).
- Windows: Service (SCM) for privileged capture, or Task Scheduler / `Run` key for user-mode MVP.
- Installed by the packaging phase (Section M, Phase 9); never required for the MVP system-proxy mode
  to *function*, only to *persist across reboots*.

### F.4 Privileges

- **MVP (system-proxy) mode runs unprivileged.** Only OS proxy settings + a loopback listener are
  touched.
- **TUN / per-app mode requires elevation** (root / admin / a helper). The daemon splits into an
  unprivileged control process and a minimal privileged helper (`ssk-netd-helper`) that only creates
  the TUN device and installs routes, over an authenticated local channel. Privilege boundary is
  explicit (Section L).

### F.5 IPC interface

- Transport: Unix socket at `$XDG_RUNTIME_DIR/kaleidoscorp/sskd.sock` (Linux), `~/Library/.../sskd.sock`
  (macOS), `\\.\pipe\kaleidoscorp-sskd` (Windows). Optional `127.0.0.1:<port>` loopback HTTP for the
  Tauri sidecar, token-gated.
- Auth: peer-credential check (SO_PEERCRED / LOCAL_PEERCRED / named-pipe SID) restricting to the same
  user, plus a per-session capability token minted at connect and required on every request.
- Protocol: request/response + server-push events, CBOR-framed (`ssk-interop` canonical + strict).
  DTOs in Section J; events in Section K.

### F.6 Health endpoint

- `get_status` (Section J) returns liveness, current state, active profile, per-adapter health,
  DNS-protection status, kill-switch status, audit-chain head, daemon version, and last error.
  Cheap, side-effect-free, always available even in `fail_closed`.

### F.7 Event stream

- A `tokio::sync::broadcast` bus. Clients call `subscribe_events` and receive typed events
  (state transitions, flow events, adapter health changes, audit appends, warnings). Backpressure:
  lagging subscribers get a `Lagged{skipped}` marker, never block the daemon. All events are also
  the source of truth the GUI renders — the GUI holds no independent network state.

### F.8 Config reload

- `config-watch` observes the config file and `import_config` IPC calls. Reload is **validated
  before apply** (fail-closed: an invalid reload is rejected, keeps the running config, emits a
  warning, does not drop protection). Applied atomically; diffs emit events so the GUI updates.

### F.9 Fail-closed, crash recovery, state persistence, audit binding

- **Fail-closed:** any condition that would allow unprotected egress (adapter unreachable, DNS
  unprotected, policy error, kill-switch armed) blocks traffic and surfaces the matching state
  (Section K). No silent direct fallback anywhere in the daemon.
- **Crash recovery:** on restart, the daemon reads persisted state (last profile, kill-switch armed?)
  and the persisted audit chain; if the previous run left the machine armed and did not cleanly
  deactivate, it comes up **fail-closed** and requires explicit user release (protects against
  crash-leak). Audit records the recovery.
- **State persistence:** minimal durable state (active profile id, kill-switch armed flag, last-known
  audit head, schema version) written atomically to `state.json` under the app data dir.
- **Audit binding:** every state-changing IPC command and every dangerous data-plane event appends to
  the **persisted** audit chain (netadmin `AuditLedger` delegating to `ssk-tensor::FileLedgerBackend`),
  so `verify_audit_chain` covers real product actions, not just a demo.

### F.10 Platform differences (summary; detail in Section H)

| Concern | Linux | macOS | Windows |
|---------|-------|-------|---------|
| IPC | Unix socket | Unix socket | named pipe |
| Autostart | systemd/XDG | launchd | Service/Task |
| Privileged helper | root helper + `CAP_NET_ADMIN` | LaunchDaemon + NE (optional) | service + WinTUN |
| MVP capture | system proxy (GNOME/env) | SystemConfiguration proxy | WinINET/WinHTTP proxy |

---

## G. Network Data-Plane Specification (`ssk-netcore`)

### G.1 Adapter runtimes (replacing descriptor-only)

Each existing descriptor in `ssk-netadmin` gains a runtime counterpart implementing `AdapterRuntime`:

| Descriptor (existing) | Runtime (new) | Real behavior |
|-----------------------|---------------|---------------|
| `DirectAdapter` (`adapter.rs:48`) | `DirectRuntime` | `TcpStream::connect(dst)` with deadline. |
| `Socks5Adapter` (`adapter.rs:76`) | `Socks5Runtime` | RFC 1928 greeting + optional user/pass (RFC 1929) + CONNECT; returns the negotiated stream. |
| `HttpConnectAdapter` (`adapter.rs:127`) | `HttpConnectRuntime` | `CONNECT host:port` + optional `Proxy-Authorization`; parse `200`; stream. |
| `TlsTunnelAdapter` (`adapter.rs:172`) | `TlsTunnelRuntime` | `rustls` client to relay with configured SNI; optional mTLS client cert; stream. |
| `DnsOverrideAdapter` (`adapter.rs:226`) | `DnsRuntime` | Resolve via configured resolver; UDP or DoT (rustls); returns resolved addrs / installs override. |

The descriptor `metadata` fields (e.g. `("sni",..)`, `("dot",..)`) are the runtime's config source —
so the existing planner output drives the runtime directly.

### G.2 Route executor

- Consumes `RouteCandidate` from `ssk_netadmin::route::RouteOrchestrator::plan` unchanged.
- `RouteKind::Direct` → `DirectRuntime` (only if policy actually chose Direct — never as a fallback).
- `SingleHop(hop)` → resolve `hop.adapter_id` in the registry → that runtime's `connect`.
- `MultiHop(hops)` → chain: hop₀ carries hop₁'s handshake, …; failure at any hop aborts the whole
  chain (no partial leak).
- `Fallback { primary, fallback }` → execute primary; on **transport** error, execute fallback; a
  policy `Denied` never triggers fallback. (This finally *runs* the `Fallback` variant that the
  planner defines at `route.rs:55-59` but never produces — the executor also asks the planner for
  fallback candidates, or config supplies them.)
- `Denied { reason }` → `Err(NetcoreError::Denied(reason))`; the daemon blocks and emits.

### G.3 Adapter registry, health, resilience

- **Registry:** `id → Arc<dyn AdapterRuntime>`, built from persisted adapter config; **unknown
  adapter id ⇒ deny** (mirrors `route.rs:150-153` fail-closed at execution time too).
- **Health checks:** periodic `health_check` per adapter; results feed `get_status` and the breaker.
- **Timeouts:** per-phase deadlines (connect, handshake, first-byte), all configurable, all with
  sane fail-closed defaults.
- **Retry policy:** bounded, jittered backoff on transient transport errors only; never retries a
  policy denial.
- **Circuit breaker:** per-adapter; after N consecutive failures the adapter opens (marked
  `unreachable`), flows using it are blocked (→ `adapter_unreachable` state), half-open probes
  attempt recovery. Opening/closing emits events.

### G.4 Invariants (enforced + tested)

1. **Unknown adapter = Deny.** No execution path resolves an unknown id to Direct.
2. **No silent direct fallback.** Direct is only ever used when the *policy* selected Direct.
3. **Denied is terminal.** `RouteKind::Denied` cannot be "recovered" into any egress.
4. **Kill-switch supremacy.** When armed and the required route is unavailable, the executor
   blocks — it does not leak.
5. **DNS honors the route.** When a route mandates DNS override, resolution that would bypass it
   is blocked, not silently system-resolved.

---

## H. OS Integration Specification

Goal: an architecturally clean progression, never a throwaway MVP. The `IngressProvider` trait is
the seam that makes system-proxy → TUN → per-app additive.

### H.1 Options per platform

| Approach | Linux | macOS | Windows | Privilege | Coverage | Product-readiness |
|----------|-------|-------|---------|-----------|----------|-------------------|
| **System proxy (MVP)** | env + GNOME/KDE proxy, or per-session | SystemConfiguration proxy | WinINET/WinHTTP proxy | user | HTTP(S)/SOCKS-aware apps | ship-able first cut |
| **TUN interface** | `/dev/net/tun` + routes | `utun` + NetworkExtension | WinTUN/Wintun | root/admin/helper | all TCP/UDP | full protection |
| **Per-app steering** | cgroup/nftables mark, or LD_PRELOAD | NE per-app (MDM) or app rules | WFP/App-ID filters | admin | selected apps | Proxifier-parity |
| **DNS** | override resolver, DoT | override resolver, DoT | override resolver, DoT | matches mode | leak prevention | required in all modes |

### H.2 Recommended order (each stage clean, none discarded)

1. **Phase-4a — System-proxy MVP.** Implement `SystemProxyProvider`: a local listener accepts
   proxied connections, builds a real `FlowRecord`, runs the existing policy/route pipeline, and
   dispatches through `ssk-netcore`. This is a *real* data plane for proxy-aware traffic and reuses
   every later layer's seam. DNS override via configured resolver.
2. **Phase-4b — TUN.** Implement `TunProvider` behind the same `IngressProvider` trait; assemble
   flows from packets, feed the *same* pipeline. Adds full-traffic coverage without changing the
   policy/route/dataplane code.
3. **Phase-4c — Per-app.** Implement `AppRuleProvider` for Proxifier-style per-app rules, mapped to
   the existing `app_id` field in `FlowDescriptor` (`flow.rs:31`) and the config `app_rules`.

### H.3 Risks (stated honestly, mitigations in Section L)

- System-proxy MVP does **not** capture non-proxy-aware apps or raw sockets → the GUI must show
  "system-proxy scope" honestly (state `dns_unprotected` / scoped-protection indicator), never claim
  full coverage.
- TUN requires elevation and correct route/kill-switch teardown or it can hard-break connectivity →
  privileged helper + guaranteed restore-on-exit + crash-recovery fail-closed.
- Per-app control is the most platform-divergent and the highest privilege → gated behind explicit,
  audited user opt-in.

---

## I. Persistent Config / Profile Specification (`ssk-config` v3)

Extends the existing versioned, migratable, fail-closed model (`crates/ssk-config/src/lib.rs:6,
160-235`) — **do not fork it**; add v3 and a v2→v3 migration next to the existing v1→v2.

### I.1 Requirements

- `version: 3`, validated (fail-closed), migratable, serde (YAML/TOML in, plus a new **atomic
  save** path — the current crate only reads).
- Secrets are **never** stored inline: config holds secret *references* resolved via `ssk-secrets`.
- Signed changes: mutating writes carry an ed25519 signature (`ssk-crypto`'s `crypto` feature) recorded in audit.

### I.2 Model (shape, not final Rust)

```
AppConfigV3 {
  version: 3,
  client: {
    active_profile: Option<ProfileId>,
    update: { channel: Stable|Beta, auto_check: bool, signature_required: true },
    logging: { level, redact_secrets: true, file: Option<Path> },
    gui_prefs: { theme, start_minimized, ... },   // opaque to the daemon
  },
  privacy_modes: [ { id, name, dns_required: bool, kill_switch: bool, min_route: RouteMode } ],
  proxy_servers: [ { id, kind: Socks5|HttpConnect|TlsTunnel|Direct|DnsOverride,
                     host, port, secret_ref: Option<SecretRef>, tls: {sni, mtls}, dns: {dot} } ],
  proxy_chains:  [ { id, name, hops: [ ProxyServerId ], fallback: Option<ChainId> } ],
  route_policies:[ /* maps onto ssk-netadmin PolicyRule/MatchCriteria/PolicyAction */ ],
  app_rules:     [ { match: {app_prefix|path|bundle_id}, action: UseChain(id)|Deny|Direct } ],
  dns_rules:     [ { match, resolver_ref|DoT, block_bypass: bool } ],
  kill_switch:   { enabled: bool, on_exit: Restore|StayClosed, block_lan: bool },
  attestation:   { required: bool, min_scheme: Mac|Ed25519, key_ref: Option<SecretRef> },
  tenant:        { tenant_id, profile_id, isolation_tag },   // reuses control.rs TenantContext
  audit:         { persist: true, path, retention },
}

Profile = a named bundle selecting { privacy_mode, chain, route_policies, dns_rules, app_rules }.
```

### I.3 Validation invariants (fail-closed)

- Referenced ids (chain hops, policy adapters, app-rule chains, dns resolvers) must resolve, else
  invalid (mirrors existing `UnknownAdapter` fail-closed at config time).
- `kill_switch.enabled` + no viable route ⇒ config is valid but the *runtime* stays fail-closed.
- `attestation.required` ⇒ a resolvable `key_ref`.
- Unknown/duplicate ids rejected (extends existing `DuplicateCapabilities` at `lib.rs:160-187`).

### I.4 Migration & compatibility

- Reuse the existing migration pattern (`parse_with_migration_*`, `LoadedConfig.migrated_from`,
  `lib.rs:141-235`). v2 configs (runtime/interop/policy/gate-profile) lift into `AppConfigV3` under a
  default single profile; `migrated_from: Some(2)` recorded and audited.

---

## J. GUI Backend API Specification (`ssk-ipc`)

Every command below is an `ssk-ipc` request with a typed request/response DTO (CBOR), an error set,
declared state effects, an audit obligation, and its GUI use. DTOs are defined once and shared by
`ssk-cli` and `ssk-tauri-bridge`. Errors map to `ssk-cli`'s existing error-class/exit-code contract.

Notation: DTOs shown as field lists; all `serde`; all responses are `Result<T, IpcError>` where
`IpcError { code, class, message, next_steps, retriable }` mirrors the CLI UX contract
(`crates/ssk-cli/tests/ux_snapshots.rs`).

| # | Command | Purpose | Request DTO | Response DTO | Key errors | State change | Audit | GUI use |
|---|---------|---------|-------------|--------------|-----------|-------------|-------|---------|
| 1 | `get_status` | Snapshot of live protection | `{}` | `StatusDto{ state, active_profile, adapters:[{id,health}], dns_protected, kill_switch, audit_head, version, last_error }` | — | none | no | Dashboard header |
| 2 | `activate_profile` | Turn protection on with a profile | `{ profile_id }` | `StatusDto` | `ConfigInvalid, RouteUnavailable, AttestationRequired, AdapterUnreachable` | `inactive→activating→(active/protected|degraded|fail_closed)` | **yes** | Big activate button |
| 3 | `deactivate` | Turn protection off | `{ release_kill_switch: bool }` | `StatusDto` | `KillSwitchArmed` | `*→inactive` (or stays fail-closed) | **yes** | Deactivate |
| 4 | `list_profiles` | Enumerate profiles | `{}` | `[ProfileSummaryDto]` | — | none | no | Profile picker |
| 5 | `create_profile` | Add a profile | `ProfileDto` | `{ profile_id }` | `ConfigInvalid` | config write | **yes** | Profile editor |
| 6 | `update_profile` | Edit a profile | `ProfileDto` | `ProfileDto` | `ConfigInvalid, NotFound` | config write | **yes** | Profile editor |
| 7 | `delete_profile` | Remove a profile | `{ profile_id }` | `{}` | `NotFound, InUse` | config write | **yes** | Profile editor |
| 8 | `list_adapters` | Enumerate adapters + health | `{}` | `[AdapterDto{ id,kind,host,port,health }]` | — | none | no | Adapters view |
| 9 | `create_adapter` | Add adapter | `AdapterDto(+secret_ref)` | `{ id }` | `ConfigInvalid` | config write | **yes** | Adapter editor |
| 10 | `update_adapter` | Edit adapter | `AdapterDto` | `AdapterDto` | `ConfigInvalid, NotFound` | config write | **yes** | Adapter editor |
| 11 | `delete_adapter` | Remove adapter | `{ id }` | `{}` | `NotFound, InUse` | config write | **yes** | Adapter editor |
| 12 | `test_adapter` | Live health probe | `{ id }` | `AdapterHealthDto{ ok, latency_ms, detail }` | `AdapterUnreachable` | none | **yes** (probe) | "Test" button |
| 13 | `list_proxy_chains` | Enumerate chains | `{}` | `[ChainDto]` | — | none | no | Chains view |
| 14 | `set_route_mode` | Set current route mode | `{ mode: Direct|Chain(id)|Policy }` | `StatusDto` | `RouteUnavailable, NotFound` | may re-route live flows | **yes** | Route selector |
| 15 | `inspect_flow` | Explain one flow's decision | `{ flow_id }` | `FlowInspectionDto{ descriptor, matched_rule, action, route, requires_attestation }` | `NotFound` | none | no | Flow detail |
| 16 | `trace_route` | Plan (or dry-run) a route for a target | `{ app_id?, dest_host, dest_port, protocol, risk }` | `RouteTraceDto{ route, hops, requires_attestation }` | `RouteUnavailable` | none | no | Route trace tool |
| 17 | `list_recent_flows` | Recent flow history | `{ limit, filter? }` | `[FlowSummaryDto]` | — | none | no | Live/flows list |
| 18 | `get_audit_entries` | Read persisted audit | `{ range?, limit }` | `[AuditEntryDto]` | — | none | no | Audit view |
| 19 | `verify_audit_chain` | Integrity check | `{}` | `{ ok, head, broken_at? }` | `AuditChainBroken` | none | **yes** | Audit "verify" |
| 20 | `run_doctor` | Environment diagnostics | `{}` | `DoctorReportDto` (reuses `doctor` checks, `main.rs:460-547`) | — | none | no | Diagnostics |
| 21 | `explain_error` | Human explanation of a code | `{ code }` | `{ summary, details, next_steps }` (reuses `explain`, `main.rs:896-969`) | `NotFound` | none | no | Error dialogs |
| 22 | `subscribe_events` | Live event stream | `{ kinds? }` | server-push `EventDto` (Section K) | — | none | no | Whole live UI |
| 23 | `export_diagnostics` | Bundle logs/state (redacted) | `{ path }` | `{ path, bytes }` | `Io` | none | **yes** | Support export |
| 24 | `export_config` | Serialize config (secrets as refs) | `{ path }` | `{ path }` | `Io` | none | **yes** | Backup |
| 25 | `import_config` | Validate + apply config | `{ path or inline, signature? }` | `{ migrated_from?, applied }` | `ConfigInvalid, SignatureInvalid` | validated reload | **yes** | Restore/apply |

Audit obligation = an append to the persisted audit chain (Section F.9). Every mutating command
requires the per-session capability token (Section F.5).

---

## K. Event and State Model

### K.1 Product states (18)

The daemon owns a single authoritative state; the GUI renders it, never invents it.

| State | Meaning | Enforcement | Typical GUI reading (not a design) |
|-------|---------|-------------|-----------------------------------|
| `inactive` | Protection off, daemon idle | traffic normal (unprotected) | neutral/off; clear "not protected" |
| `activating` | Bringing protection up | transitional; fail-closed if it can't complete | progress/spinner state |
| `active` | Protection on, routing engaged | enforcing | positive but pre-verified |
| `protected` | Active **and** DNS + route verified | enforcing, verified | strongest positive/confirmed |
| `degraded` | Active but a non-fatal issue (one adapter down, using fallback) | still enforcing, reduced | caution; explain what's reduced |
| `fail_closed` | Cannot guarantee protection → traffic blocked | blocking | prominent, deliberate "blocked to protect you" |
| `disconnected` | Upstream/relay lost | blocking (kill-switch) or reconnecting | warning + recovery affordance |
| `adapter_unreachable` | Required adapter/circuit open | blocking flows via it | warning naming the adapter |
| `dns_unprotected` | DNS not covered (e.g. MVP scope) | may still route; DNS leak risk | honest scoped-protection warning |
| `policy_error` | Policy engine could not decide safely | fail-closed | error; link to policy inspection |
| `config_invalid` | Config failed validation | protection off, GUI can edit | blocking config banner |
| `route_unavailable` | No viable route for the selection | fail-closed | error; suggest another chain |
| `attestation_required` | Route needs attestation not yet satisfied | held/blocked until satisfied | prompt for attestation |
| `attestation_failed` | Attestation invalid | fail-closed | security error |
| `audit_warning` | Audit chain verify found an issue | non-blocking but flagged | tamper/integrity warning |
| `daemon_unreachable` | GUI/CLI can't reach daemon | client-side only | "backend not running" |
| `updating` | Update in progress | protection maintained if possible | update banner |
| `recovery_mode` | Post-crash safe mode, came up fail-closed | blocking until user releases | recovery prompt + audit reference |

### K.2 Transition rules (selected)

- `inactive → activating` on `activate_profile`; `activating → protected` iff route up **and** DNS
  covered **and** (attestation satisfied if required); else `→ degraded`/`fail_closed`/`route_unavailable`/`attestation_*`.
- Any state → `config_invalid` on a rejected reload keeps the *previous running* enforcement (reload
  is validated-before-apply; the state flags the bad file without dropping protection).
- Any active state → `fail_closed` on kill-switch trigger, `adapter_unreachable`, `policy_error`,
  `attestation_failed`, or DNS-bypass detection.
- Crash → `recovery_mode` (fail-closed) if previously armed; explicit user release → `activating`.
- `daemon_unreachable` is a client-observed state (not a daemon state), shown when IPC is down.

### K.3 Event classes (`EventDto`)

```
Event =
  | StateChanged { from, to, reason }
  | FlowEvent { flow_id, descriptor, action, route, outcome, bytes, ts }
  | AdapterHealth { adapter_id, health, breaker }
  | AuditAppended { seq, entry_hash, outcome }
  | Warning { code, class, message, next_steps }
  | UpdateProgress { phase, pct }
  | Lagged { skipped }        // backpressure marker
```

### K.4 Error classes & recovery paths

Reuse and extend `ssk-cli`'s error-class model and `NetAdminError`
(`crates/ssk-netadmin/src/error.rs:6-25`). Each error maps to: a state, a machine code, a class, an
exit code (for CLI), and `next_steps`. Recovery examples: `RouteUnavailable` → offer alternate
chain / Direct (only if user explicitly allows); `AdapterUnreachable` → breaker half-open probe +
`test_adapter`; `ConfigInvalid` → open editor, re-validate; `AuditChainBroken` → export diagnostics,
freeze writes, alert.

---

## L. Security and Privacy Guarantees

### L.1 What the product guarantees

- **Fail-closed default.** No configuration path yields silent unprotected egress; the default and
  the error paths block. (Enforced by `ssk-netcore` invariants G.4 + daemon F.9.)
- **No silent bypass / no silent direct fallback.** Direct egress happens only when policy explicitly
  selects Direct; unknown adapters and `Denied` routes always block.
- **Kill switch.** When armed, loss of the required route blocks traffic (incl. LAN if configured),
  including across daemon crash (recovery-mode fail-closed).
- **Tamper-evident, persisted audit.** All dangerous/state-changing actions append to a BLAKE3
  hash-chained ledger. **Done** (Phase 1): `ssk-netadmin`'s `AuditLedger`/`SessionLedger` are generic
  over `ssk_tensor::GenericLedgerBackend<E>` with a `::persisted(path)` constructor delegating to
  `ssk-tensor`'s (now-generalized) `GenericFileLedgerBackend`; `verify()` detects mutation/gaps across
  a process restart. Wiring this into the live daemon's audit binding is still Phase 6 work.
- **Secret redaction & isolation.** Secrets live in the OS keychain (`ssk-secrets`), are zeroized in
  memory, are referenced (not inlined) in config, and are redacted from logs/diagnostics.
- **Signed config changes.** Mutating config is ed25519-signed (`ssk-crypto`'s `crypto` feature,
  `Ed25519KeyPair`) and audited.
- **Secure updates.** Signature verification is mandatory; rollback to last-known-good is available.
- **Local-only IPC authentication.** Peer-credential + per-session token; same-user only.
- **Explicit privilege boundary.** Privileged capture runs in a minimal, separate helper.

### L.2 What the product does **not** guarantee (must be stated in-product)

- **Not anonymity.** The system steers/blocks/audits traffic; it does not by itself provide
  network-level anonymity or unlinkability. `ssk-privacy` is a risk heuristic (`ssk-privacy/src/lib.rs`),
  not a correlation/anonymity engine.
- **MVP scope is partial.** System-proxy mode protects only proxy-aware traffic; non-proxy apps and
  raw sockets are **not** covered until TUN. The GUI must display this scope honestly (state
  `dns_unprotected` / scoped indicator).
- **No traffic-content confidentiality claim** beyond what the chosen adapters' TLS actually provides.

### L.3 Forbidden claims (correct the current docs)

The following were **false or overstated**; items 2 and 4 are now fixed (Phase 1), item 1 has a real
alternative available but the *default* attestation scheme is still the symmetric MAC, and item 3
remains unclaimable until the Phase 3 data plane ships:

1. "Cryptographically **signed** attestation" — `ssk-netadmin::AttestationBinder` and
   `ssk-interop::Blake3KeyedVerifier` still *default* to a **symmetric** BLAKE3 keyed-MAC
   (`ssk-interop/src/lib.rs`, `ssk-netadmin/src/attestation.rs`) — call this "keyed-MAC attestation."
   A real asymmetric alternative now exists (`ssk_crypto::Ed25519KeyPair`/`Ed25519Verifier`, behind
   the `crypto` feature) and may be called "ed25519-signed attestation" **only** where it is actually
   used — wiring it into `AttestationBinder` itself is not yet done.
2. **Fixed.** "Zero-key constructors are compile-time restricted to test builds" (`SECURITY.md:47-49`)
   is now true: `Blake3KeyedVerifier::new`/`AttestationBinder::new` unconditionally reject an all-zero
   key; a separate `new_test_key()` (gated by `cfg(test)`/the `insecure-test-keys` feature, off by
   default) supplies the fixed reference key. `ssk-cli` is the one shipped binary that opts
   `ssk-interop` into that feature (for its `interop conformance` self-test only); `ssk-netadmin`'s
   `AttestationBinder` has no such exception anywhere.
3. "In-process **Proxifier replacement** / cryptographically-audited traffic **routing**" while
   adapters are descriptor-only and no bytes move (`adapter.rs:5-9`, `route.rs:117-128`). Only claim
   this once `ssk-netcore` + `ssk-capture` ship and pass the Section-N data-plane tests.
4. **Fixed.** `DataPlaneAdapter::connect()` in `NETADMIN_SPEC.md` has been removed from the documented
   trait; the spec now matches the real `describe()`-only trait and points to the Phase 3
   `ssk-netcore::AdapterRuntime::connect` runtime layered alongside it.

### L.4 Threat-model boundaries

Local attacker with same-user privileges is out of scope for IPC (they already control the session);
the boundary is other users and remote parties. Config-at-rest and secrets are protected by the OS
keychain + AEAD sealing; audit integrity is protected by the hash chain; update integrity by
signatures.

---

## M. Implementation Phases

Each phase lists crates/files, key APIs, tests, and acceptance criteria. Phases are additive; nothing
built is later discarded. "AC" = acceptance criteria (executable).

### Phase 1 — Core completion & honesty pass — **done**
- Crates: `ssk-tensor` (generalized), `ssk-netadmin`, `ssk-crypto`, `ssk-interop`, `ssk-cli`, `SECURITY.md`, `NETADMIN_SPEC.md`.
- Work: generalized `ssk-tensor`'s `LedgerBackend`/`MemoryBackend`/`FileLedgerBackend` to be generic
  over the entry type (via a `GenericLedgerBackend<E>` storage trait + type aliases, preserving the
  old API); wired `ssk-netadmin`'s `AuditLedger`/`SessionLedger` to real disk persistence via
  `AuditLedger::persisted(path)`/`SessionLedger::persisted(path)`; implemented ed25519
  (`Ed25519KeyPair`/`Ed25519Verifier`) + ChaCha20-Poly1305 (`ChaCha20Poly1305Provider`) directly in
  `ssk-crypto` behind its existing `crypto` feature (no new `ssk-signing` crate); feature-gated the
  zero-key constructors (`Blake3KeyedVerifier::new`/`AttestationBinder::new` now reject an all-zero
  key unconditionally; `new_test_key()` is the explicit, narrowly-scoped exception — only `ssk-cli`
  opts `ssk-interop` into it, for the real `interop conformance` production call site that needed the
  fixed reference key); corrected `SECURITY.md`/`NETADMIN_SPEC.md`/this doc's forbidden claims (L.3).
- Tests: `ssk-tensor` generic-backend unit tests; `ssk-netadmin`'s `persisted_chain_survives_reopen`
  (audit + session); `ssk-crypto/tests/ed25519_vectors.rs` (9 tests: sign/verify round-trip, tamper
  detection, deterministic seed, AEAD round-trip/tamper/AAD-mismatch); `new_rejects_zero_key` in both
  `ssk-interop` and `ssk-netadmin::attestation`. All existing tests (including `ux_snapshots.rs`)
  pass unmodified.
- AC verified: `verify()` passes on both ledgers after a real process restart at the same path; a
  plain `cargo build --release -p ssk-netadmin` (no feature flags) rejects `AttestationBinder::new([0u8;32])`;
  `cargo test --workspace`/`cargo clippy --workspace --all-targets -- -D warnings` are green.

### Phase 2 — Daemon + IPC
- Crates: `ssk-daemon` (new, bin `sskd`), `ssk-ipc` (new).
- APIs: Section J commands 1–4, 15–22 (status/activate/deactivate/list + inspect/trace/audit/doctor/explain/subscribe); event bus (K.3); state machine (K.1) minus data-plane-dependent states.
- Tests: IPC round-trip (CBOR strict), peer-cred auth rejects other users, event subscription + backpressure `Lagged`, state transitions for activate/deactivate against a **mock** data plane.
- AC: `ssk-cli` drives `sskd` over IPC for status/activate/deactivate; a second user cannot connect; killing a daemon task moves state to `degraded`/`fail_closed` and emits an event.

### Phase 3 — Adapter runtime (real data plane)
- Crate: `ssk-netcore` (new).
- APIs: `AdapterRuntime` + `DirectRuntime/Socks5Runtime/HttpConnectRuntime/TlsTunnelRuntime/DnsRuntime`; `RouteExecutor`; `AdapterRegistry`; health/timeout/retry/circuit-breaker.
- Tests: against local test servers — SOCKS5 handshake reaches an echo server; HTTP CONNECT parses 200; TLS tunnel completes with a test CA; multi-hop chains two local proxies; fallback triggers on primary transport failure; **unknown adapter denies**; **Denied never egresses**; breaker opens after N failures.
- AC: a real byte round-trip through each adapter to a local echo server; killing an adapter mid-flow → `adapter_unreachable`, **no** Direct fallback; `Denied` yields a blocked flow event, never a connection.

### Phase 4 — OS network integration (system-proxy MVP → TUN → per-app)
- Crate: `ssk-capture` (new), `ssk-daemon` wiring, `ssk-netd-helper` (privileged, Phase 4b).
- 4a `SystemProxyProvider` (unprivileged): local listener → real `FlowRecord` → pipeline → `ssk-netcore`; DNS override; OS proxy set/restore per platform. 4b `TunProvider` + helper. 4c `AppRuleProvider`.
- Tests: with the MVP active, a proxy-aware client's request is actually routed through the selected chain and audited; disabling the daemon **restores** OS proxy; TUN teardown restores routes even after SIGKILL (recovery fail-closed).
- AC: end-to-end — configure a chain, activate, observe a real external request traverse it in `list_recent_flows` + audit; kill-switch blocks when the chain is down; OS networking is cleanly restored on deactivate/crash.

### Phase 5 — Persistent config & profile model
- Crate: `ssk-config` v3 + save path; `ssk-secrets` (new).
- APIs: `AppConfigV3` (Section I), atomic save, v2→v3 migration, secret refs; Section J commands 5–14, 24–25 (CRUD + import/export).
- Tests: v2 config migrates to v3 (`migrated_from:2`); invalid refs rejected fail-closed; secrets never serialized inline; round-trip export/import.
- AC: GUI/CLI can create/edit/delete profiles, adapters, chains; config survives restart; a secret is stored in the OS keychain and only referenced in the exported config.

### Phase 6 — Event stream & audit persistence hardening
- Crates: `ssk-daemon`, `ssk-netadmin`, `ssk-tensor`.
- Work: complete the live flow-event stream from `ssk-capture`/`ssk-netcore`; bind every dangerous action to the persisted audit; retention/rotation.
- Tests: every activate/deactivate/route-change/adapter-test appears in the persisted audit; chain verifies after rotation; flow events stream to a subscriber in real time.
- AC: `get_audit_entries` + `verify_audit_chain` reflect real product actions across restarts; the live flow list updates as traffic flows.

### Phase 7 — Tauri backend bridge
- Crate: `ssk-tauri-bridge` (new).
- APIs: `#[tauri::command]` wrappers over the Section-J DTOs; event relay to the webview; secret hand-off only to the authenticated local GUI on explicit audited request.
- Tests: each Tauri command maps 1:1 to an IPC DTO; no command shells out; error mapping preserves code/class/next_steps.
- AC: a minimal Tauri harness calls every Section-J command and receives typed results + live events; no CLI-scraping anywhere.

### Phase 8 — GUI readiness
- Deliver a stable, versioned DTO/event contract, a frontend state model doc (maps states K.1 + events K.3 to view state), and fixtures for every state.
- AC: the GUI team can render all 18 states and all event classes from recorded fixtures without a running daemon.

### Phase 9 — Packaging, signing, updater
- Crate: `ssk-updater` (new) + platform installers (systemd/launchd/Service, autostart), code signing/notarization.
- AC: signed installers per OS; auto-update verifies signatures and can roll back; realizes `docs/ROADMAP_DESKTOP_GUI.md` packaging + auto-update.

### Phase 10 — Cross-platform hardening
- Chaos/soak/leak tests on all three OSes; privilege-boundary audit; kill-switch leak testing; performance.
- AC: Section-N chaos + leak matrix green on Windows/macOS/Linux; no leak under adapter/DNS/daemon failure injection.

---

## N. Test Matrix

| Layer | Type | What it proves | Where |
|-------|------|----------------|-------|
| Control plane | unit | policy/route-plan/attestation/ledger logic (existing) | `crates/ssk-netadmin/**`, `ssk-runtime/**` |
| Config | unit | v3 validate/migrate/save, secret-ref resolution | `ssk-config` |
| Signing | unit/vectors | ed25519 sign/verify, key handling — **done** | `ssk-crypto/tests/ed25519_vectors.rs` |
| Data plane | integration | real handshakes to local test servers per adapter; multi-hop; fallback | `ssk-netcore/tests` |
| Data plane | conformance | SOCKS5/HTTP-CONNECT/TLS wire correctness | `ssk-netcore/tests` |
| Invariants | integration | unknown-adapter-deny, no-direct-fallback, Denied-terminal, kill-switch supremacy, DNS-no-bypass | `ssk-netcore/tests` |
| OS ingress | os-integration | proxy set/restore, TUN teardown after SIGKILL, real external round-trip | `ssk-capture/tests` (per-OS CI) |
| IPC | integration | CBOR strict round-trip, peer-cred auth, token, backpressure | `ssk-ipc/tests` |
| Daemon | integration | state transitions, config reload validated-before-apply, crash→recovery fail-closed | `ssk-daemon/tests` |
| Audit | integration | persisted chain verify across restart + rotation; dangerous-action binding | `ssk-daemon/tests` |
| Replay | integration | deterministic decision replay (existing) still holds through the service | reuse `ssk-runtime/tests` |
| Chaos | chaos | fault injection (adapter down, DNS fail, daemon crash) never leaks | extend `ssk-faultscan` wired to real gate vector |
| Security | security | zero-key rejected in release, redaction, signed-config enforcement, IPC rejects other users | cross-crate |
| GUI contract | fixture | all 18 states + event classes renderable from fixtures | `ssk-tauri-bridge/tests` |

CI runs the OS-integration and chaos/leak matrices on Windows, macOS, and Linux (Phase 10).

---

## O. Agent Implementation Prompt

A standalone, directly-usable prompt for the coding agent that will implement this architecture is
maintained separately at **`docs/AGENT_IMPLEMENTATION_PROMPT.md`**. It is scoped to start at Phase 1
and Phase 2, references this document as the source of truth, and carries the quality guardrails
(no attrappen, no throwaway MVP, every current-state claim file-cited, fail-closed everywhere,
truthful product claims). Use that file verbatim to kick off implementation.

---

### Quality rules honored by this specification

- No dummies: every target component has a real, testable behavior.
- No throwaway MVP: the system-proxy MVP is a real data plane behind the `IngressProvider` seam and
  is not discarded by TUN/per-app.
- No GUI illusion: the GUI renders only daemon-enforced state; forbidden claims are enumerated (L.3).
- No false privacy promises: guarantees and non-guarantees are explicit (L.1/L.2).
- No invented existing features: every "current state" claim cites a repository file.
- Every target component is implementable, testable, and layered so the control plane never depends
  on the data plane. Shelf-ready, not demo-ready.
