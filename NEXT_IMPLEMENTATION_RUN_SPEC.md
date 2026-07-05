# NEXT_IMPLEMENTATION_RUN_SPEC.md

> **IMPLEMENTATION UPDATE (this run executed against this spec, same day).** **WP1 (no_std fix), WP2 (`ssk-netcore` real adapter model), WP3 (daemon/system integration replacing `MockDataPlane`), WP4 (CLI user-reachable flow — `ssk activate --dest`), and the audit-non-vacuous half of WP5 are DONE** — see `crates/ssk-netcore/` (new crate: real Direct/SOCKS5/HTTP-CONNECT/TLS/DNS execution + health probing), `crates/ssk-daemon/src/supervisor.rs` + `main.rs` (mock removed from production, real destination required, real audit recording), `crates/ssk-cli/src/main.rs` (`Activate { profile, dest }`), and the real-binary system tests `ssk-daemon/tests/round_trip.rs` + `ssk-cli/tests/activate_real_egress.rs`. The bonus `cargo deny`/`bans` wildcard-dependency fix (all 23 crates) was also applied. **Still open, exactly as this spec originally scoped**: WP5's TTL-sweep-driver half (`DissolutionManager::sweep` still has no production caller), WP6 (config/profile/policy — the daemon still uses one hardcoded reference policy, not a config-driven multi-profile model), WP7 (a dedicated unit/integration/system test-tier split beyond what the new real-binary tests already establish), and WP8's packaging half (release still ships source, not binaries; no service units). The Definition of Done items below should be re-checked against this update, not assumed satisfied — items 1, 2 (partially: WP1 fully; SSKΩ-7 now real for adapters, not merely corrected in prose), 3, and 4 are now substantively true; items 6-9 need re-verification per WP6/WP7/WP8's remaining scope.

> Implementable master spec for the next implementation run of the SSK-Ω (`kaleidoscorp.io`) workspace.
> Ground truth: the frozen audit evidence (Iterations A–F), the adversarial verdicts (A–G), and the SSK-Ω ladder re-evaluation. Every strong claim below carries a `file:line` or test citation drawn from that evidence. This document is written to be executed against, not to be read as marketing.

---

## 0. Preface — what this repository actually is today

Read this before planning any work. The audit and the code's own honesty markers agree on the following baseline.

**What exists and works (as a code artifact, maturity ~level 4 — locally executable, deterministic, tested):**

- A real, internal, deterministic decision-core pipeline: `run_to_outcome` at `crates/ssk-runtime/src/lib.rs:230-314` runs a real scheduler tick, real identity/locator/stitch/gate stages, a **real cryptographic BCIK crossing** (`ssk_bcik::Bcik::cross` at `crates/ssk-runtime/src/lib.rs:268-283`), a **real persistent in-memory tensor mutation** (`StitchTensor::apply_sorted` at `crates/ssk-tensor/src/lib.rs:153`), and **real concave focus** (`FocusEngine::reanalyze` at `crates/ssk-runtime/src/lib.rs:302`).
- A genuinely fail-closed 12-gate vector (`crates/ssk-gates/src/lib.rs:381-417`, default-deny in the final `else` arm `:407-408`, no early break, proven by `all_twelve_gates_are_evaluated_even_after_an_early_reject` `lib.rs:603-629`).
- A compile-time typestate machine that makes fail-closed materialization a property of the API shape (`materialize` defined only on `impl Connection<GatePassed>`, `crates/ssk-core/src/connection.rs:201-217`).
- A genuine re-execution replay engine (`crates/ssk-replay/src/lib.rs:55`, diffs freshly recomputed digests against a commitment manifest, `:57-70`).
- A real local control plane: `sskd` driven cross-process over a real Unix domain socket, tested in `crates/ssk-daemon/tests/round_trip.rs:28,46`; real state machine + supervised-failure watchdog (`crates/ssk-daemon/src/supervisor.rs:87-109`).
- A real, strict, fail-closed config **validator** (`crates/ssk-config/src/lib.rs:724-762`) with real forward migration (`:794-844`).
- Real hash-chained ledger backends and a real policy/route **planner** in `ssk-netadmin` (`crates/ssk-netadmin/src/policy.rs:138-157`, `route.rs:127-180`).

**What does NOT exist (the product contract's headline capability):**

- **No network data plane.** The terminal executor of the core pipeline is `LocalFiberExecutor` (`crates/ssk-runtime/src/lib.rs:189-213`), which by its own doc "fabricates no network liveness" (`:176-178`); its `payload_digest` is a Blake3 hash of the stitch's own fields (`:195-204`). No TCP/UDP/TLS/DNS packet leaves the process anywhere in the workspace.
- **No `ssk-netcore` crate** (Phase 3 route executor) and **no `ssk-capture` crate** (Phase 4 ingress). Both confirmed absent (`ls crates/ssk-netcore`, `ls crates/ssk-capture` → No such file or directory).
- **Descriptor-only adapters.** `trait DataPlaneAdapter` has exactly `adapter_id()` and `describe()` — no `connect()` (`crates/ssk-netadmin/src/adapter.rs:37-40`); the module doc concedes adapters are "descriptor-only … the actual transport is the responsibility of the caller" (`adapter.rs:5-9`). The crate has no `tokio`/`std::net`/`rustls`/`hyper`/`socket2` dependency (`crates/ssk-netadmin/Cargo.toml:15-23`).
- **Mock daemon data plane.** `AlwaysUpMockDataPlane::route_available` returns `true` unconditionally (`crates/ssk-daemon/src/mock_dataplane.rs:17-21`), wired into the production binary at `crates/ssk-daemon/src/main.rs:53`. `GetStatus` hardcodes `dns_protected=false`, `kill_switch=false` (`supervisor.rs:251-252`); `ListRecentFlows` returns `[]` (`supervisor.rs:397-401`).

**Two hard falsifiers of any "done / production-ready" claim, confirmed in this tree:**

1. **The `no_std` guarantee is broken.** `cargo check -p ssk-core --no-default-features` fails (exit 101, E0425/E0433 "cannot find type `Vec`") at `crates/ssk-core/src/connection.rs:55,78,87` (bare `Vec`, no `use alloc::vec::Vec`). README advertises this exact configuration as CI-verified (`README.md:102,342-343,371`; CI job `.github/workflows/ci.yml:75-81`).
2. **SSK-Ω-7 is self-graded ⚠️ and unmet.** The one rung whose own definition requires "real egress adapters behind the async edge, health probing" is deferred to the absent `ssk-netcore` (`docs/OMEGA_CORE_CONFORMANCE_SPEC.md:256`). This contradicts the summary claim at `:39` that SSK-Ω-0 through SSK-Ω-9 are all met.

**Honesty note carried forward:** the code and the live daemon status are largely truthful about incompleteness (`dns_protected=false`, empty flows, "unknown (ssk-netcore not yet integrated)" adapter health at `supervisor.rs:249`, explicit Phase-N comments). The overclaims live in `README.md`, `docs/NETADMIN_SPEC.md`, `docs/COMPLETION_CHECKLIST.md`, and the `docs/OMEGA_CORE_CONFORMANCE_SPEC.md:258` SSK-Ω-9 "✅ met" marker — not in the running binary. `docs/DESKTOP_CLIENT_ARCHITECTURE.md` is itself an internal honesty audit (its Section B.6 is titled "Doc-vs-code discrepancies to correct") and should be treated as the corrective baseline.

---

## 1. Target state — what is really different after the next run

The next run is scoped to **turn the strongest overclaims into either real, minimally-executable capabilities or cleanly-labeled, fail-closed unimplemented boundaries**, and to make the maturity of every headline capability legible. It is explicitly **not** scoped to ship a full Proxifier replacement.

### 1.1 What counts as done for this run

A capability is "done" for this run only if it satisfies the Definition of Done in §4. Concretely, after this run:

1. **`ssk-core` compiles under `--no-default-features`.** `cargo check -p ssk-core --no-default-features` exits 0, and the `no_std_core` CI job (`ci.yml:75-81`) is green on the branch. (WP1)
2. **A real `ssk-netcore` crate exists** exposing a `RouteExecutor` trait with a real method that opens a real, local, lawful egress (loopback TCP + local DNS resolution behind explicit capability probes), plus a fail-closed `NullRouteExecutor` for environments without the capability. The daemon's `MockDataPlane` is replaced by a `RouteExecutor`-backed data plane. (WP2, WP3)
3. **`GetStatus` reports truthfully.** `dns_protected`, `kill_switch`, and adapter health reflect the real `RouteExecutor` state instead of hardcoded constants. When no real executor is active, they report the honest "unprotected / unimplemented" state with a machine-readable reason — never a fabricated `true`. (WP3)
4. **The CLI `connect` verb no longer implies a network connection it does not perform.** Either it is renamed to `materialize`/`simulate-intent` (matching `LocalFiberExecutor`'s actual effect), or a real `connect` is gated behind `ssk-netcore` capability probes and cleanly refuses with a fail-closed reason when the data plane is absent. (WP4)
5. **The daemon actually records to its audit ledger**, so `VerifyAuditChain` verifies a non-empty chain instead of a vacuous empty one (`supervisor.rs` currently has no `.record()` call; `VerifyAuditChain` is vacuous per `round_trip.rs:106`). (WP5)
6. **TTL sweep runs from a real driver** (daemon epoch tick), residues land in a persisted hash-chained ledger, and a user-observable surface exists — replacing the current zero-caller library function (`crates/ssk-tensor/src/lib.rs:211,218,237-259`, no callers outside defs + `#[cfg(test)]`). (WP5)
7. **Config reaches runtime behavior.** The validated `AppConfig` is threaded into `Supervisor` and `ssk-netadmin`, retiring the hardcoded `reference_policy_engine()` (`supervisor.rs:112-147`). Today config is parsed then discarded (`crates/ssk-daemon/src/main.rs:38-53`). (WP6)
8. **The conformance suite is explicitly partitioned** into unit / model-property / integration / system tiers, with a real system-level test that drives an actual local socket egress end-to-end (or is clearly marked "no system tier exists yet" — never a model test relabeled as a system test). (WP7)
9. **Packaging and docs are honest.** The release workflow ships the built binaries, not only a source tarball (`release.yml:19-20` vs claim `README.md:381`); the doc maturity statements are corrected against the evidence. (WP8)

### 1.2 What is explicitly NOT done after this run (declared non-goals for this run)

These remain unimplemented and MUST be documented as such — not claimed. They are legitimate future work, not defects to hide:

- **No full Proxifier replacement.** SOCKS5/HTTP-CONNECT/TLS-tunnel handshakes and split-horizon DNS override against arbitrary remote hosts are NOT delivered this run. Only a minimal, local, lawful egress capability (loopback TCP, local resolver) is delivered to prove the `RouteExecutor` boundary is real and fail-closed.
- **No traffic capture / ingress.** `ssk-capture` (Phase 4) is not created this run; `ListRecentFlows` continues to return real captured flows only if capture exists — otherwise it stays honestly `[]` with a documented reason.
- **No desktop GUI / Tauri client / updater.** `docs/DESKTOP_CLIENT_ARCHITECTURE.md:201` confirms none exist; this run does not create them.
- **No asymmetric attestation migration to production default.** Attestation remains the symmetric Blake3 keyed-MAC by default (`crates/ssk-netadmin/src/attestation.rs:86-132`; honesty marker `docs/DESKTOP_CLIENT_ARCHITECTURE.md:108-110`). This run only corrects the docs that call it "signed capability attestation."
- **No cross-platform matrix or service hardening beyond SIGTERM + lock cleanup.** Full systemd/launchd packaging and multi-OS CI are out of scope beyond the minimal unit file + signal fix in WP8.

Anything on this list that later gets claimed as "done" without the corresponding acceptance test is a regression against this spec.

---

## 2. Maturity ladder used in this document

The SSK-Ω ladder in `docs/OMEGA_CORE_CONFORMANCE_SPEC.md:249-258` is a **core-decision-model** ladder, not a network-product ladder. To avoid the category error the audit repeatedly flags, every capability below is graded on **two axes**:

- **Artifact maturity** (0–7): is the code locally executable, deterministic, tested?
- **Product-capability maturity** (0–7): does it produce a real network/system effect a user can reach?

Example of the gap this exposes: the core pipeline is artifact-level 4 but product-capability level 2 (Verdict A). `select_egress`/`HypercubePathCheck` is artifact-level 3–4 but product-capability level 1, and is not user-reachable at all (Verdict B, `crates/ssk-runtime/src/lib.rs:833,835,845,850,862,866` — only test callers). Never report the artifact grade as if it were the product grade.

---

## 3. Work Packages

### WP1 — Core cleanup / boundary correction (`ssk-core` `no_std` fix + honest labels)

**Goal.** Restore the advertised `no_std` guarantee and correct the in-code and doc labels that overclaim the abstract core as a product capability. This is the cheapest, highest-credibility fix in the run: it turns a broken CI-advertised guarantee green.

**Files / crates.**
- `crates/ssk-core/src/connection.rs` (the regression source: bare `Vec` at `:55`, `:78`, `:87`; imports only `use core::marker::PhantomData` at `:18`).
- `crates/ssk-core/Cargo.toml` (declares `default = ["std"]`, `std = ["ssk-types/std"]` at `:7-9`).
- `crates/ssk-stitch/src/lib.rs:5-23` (candidate builder that hardcodes `seam_ok/boundary_complete/replay_ready/focus_ready = true` at `:17-20`).
- Doc labels: the `run_to_outcome` doc comment (`crates/ssk-runtime/src/lib.rs:215-225`), `README.md` prose that implies delivered routing.

**New / changed APIs.**
- No public API change. Add `extern crate alloc;` (guarded for the no_std path) and `use alloc::vec::Vec;` to `connection.rs` so the bare `Vec` uses at `:55,78,87` resolve. Mirror the pattern already used by `ssk-types` for its no_std build.
- Optionally, make `ssk_stitch::from_intent` derive `seam_ok/boundary_complete/replay_ready` from real candidate state rather than hardcoding `true` (`crates/ssk-stitch/src/lib.rs:17-20`) so SSK-Ω-3's "carries seam/boundary/replay" is validated, not asserted. If deferred, document it as a known limitation.

**Invariants.**
- `ssk-core` MUST build under both `--features std` (default) and `--no-default-features`.
- No behavior change to the typestate transitions (`connection.rs:143-217`); this is a build-hygiene fix, not a logic change.

**Failure modes.**
- Missing `alloc` in the target environment → the crate must fail to compile with a clear error, not silently pull in `std`.

**Tests.**
- CI job `no_std_core` (`ci.yml:75-81`) must go green; verify `cargo check -p ssk-core --no-default-features` exits 0.
- Keep the existing trybuild typestate compile-fail tests (`crates/ssk-core/tests/ui.rs`) green.
- If `from_intent` is changed: add a unit test that a candidate built from an intent lacking seam data does NOT get `seam_ok = true`.

**Acceptance criteria.**
- `cargo check -p ssk-core --no-default-features` exits 0; `cargo check -p ssk-types --no-default-features` still exits 0.
- The README `no_std` claim (`README.md:102`) is now truthful, OR the claim is removed from README+CI in the same change. No middle state.

**Non-goals.**
- Do not attempt to make `ssk-runtime`/`ssk-gates` no_std this run; the guarantee is scoped to `ssk-types` and `ssk-core` per `README.md:80-81`.

---

### WP2 — Netcore real adapter model (`ssk-netcore` `RouteExecutor`)

**Goal.** Create the missing `ssk-netcore` crate with a real `RouteExecutor` trait that turns a planned `RouteCandidate` into an actual, local, lawful egress — proving the descriptor-only adapter boundary can be crossed, and doing so behind explicit capability probes with fail-closed reasons. This is the smallest change that moves the network product capability off product-level 2 for a bounded, honest surface.

**Files / crates.**
- New crate `crates/ssk-netcore/` (currently absent — confirmed).
- Consumes `crates/ssk-netadmin/src/route.rs` (`RouteCandidate`, `RouteKind`, `HopSpec { address, port, auth }` at `route.rs:14-23`, described "ready for dispatch" at `:60` but never dispatched today).
- Consumes `crates/ssk-netadmin/src/adapter.rs` descriptors (`AdapterDescriptor`, `DnsOverrideAdapter` fields at `adapter.rs:218-262`).

**New / changed APIs.**
```
// crates/ssk-netcore/src/lib.rs
pub trait RouteExecutor {
    /// Probe whether this executor can actually perform egress in the
    /// current environment (capability check: socket permission, resolver
    /// reachability). MUST NOT open the target connection.
    fn probe(&self) -> Result<Capabilities, ExecError>;

    /// Execute a planned route. On success returns a live handle; on any
    /// missing capability returns a fail-closed ExecError with a machine
    /// -readable reason. MUST NOT silently fall back to unprotected egress.
    fn execute(&self, route: &RouteCandidate) -> Result<SessionHandle, ExecError>;

    fn teardown(&self, handle: SessionHandle) -> Result<(), ExecError>;
}

pub struct Capabilities {
    pub raw_tcp: bool,
    pub dns_resolve: bool,
    pub dns_override: bool,   // false this run — declared non-goal
    pub tls_tunnel: bool,     // false this run — declared non-goal
}

pub enum ExecError {
    CapabilityUnavailable { capability: &'static str, reason: String },
    RouteDenied { reason: String },       // planner said Denied
    AdapterUnsupported { kind: RouteKind }, // e.g. SplitRoute this run
    TransportFailed { source: std::io::Error },
}
```
- `DirectRawTcpExecutor` — a **real** implementation that opens a real TCP connection using `tokio::net::TcpStream` / `std::net` to a **loopback or explicitly-allowlisted local address only** this run. This is the honest, lawful minimum that makes `DirectAdapter` = "Raw TCP" (`README.md:283-292`) partially true for a bounded target set, instead of an empty descriptor (`adapter.rs:63-71`).
- `NullRouteExecutor` — returns `ExecError::CapabilityUnavailable` for every `execute`, and `Capabilities { all false }` from `probe`. This is the fail-closed default when no real egress is permitted/available.
- `ssk-netcore/Cargo.toml` gets the network dependency (`tokio` with `net`, or `std::net`) that `ssk-netadmin` deliberately lacks. Keep `ssk-netadmin` transport-free.

**Invariants.**
- **Fail-closed transport.** `execute` MUST return an `ExecError` (never a usable handle) when `probe` reports the required capability false. No code path may open unprotected egress as a "fallback." This mirrors the planner's existing fail-closed default (`route.rs:127-180`) at the execution layer, which today has "no enforcement teeth" (per WP verdict on `ev:netadmin`).
- **Only the planner's non-denied routes reach `execute`.** `RouteKind::Denied` (`route.rs:134-145`) maps to `ExecError::RouteDenied`; the executor never re-decides policy.
- **Reserved audit outcomes become producible.** `AdapterUnreachable`, `KillSwitchBlocked`, `FallbackDispatched` (`crates/ssk-netadmin/src/audit.rs:31-42`, currently "Not yet produced by any code path until ssk-netcore ships") get real producers wired from `ExecError`.

**Failure modes (all must be explicit, fail-closed, and diagnosable).**
- No socket permission → `CapabilityUnavailable { capability: "raw_tcp", reason }`.
- Target outside the local allowlist → `RouteDenied` (do not attempt).
- `SplitRoute` / multi-hop → `AdapterUnsupported` (declared non-goal this run; never a silent no-op).
- Local resolver unreachable → `CapabilityUnavailable { capability: "dns_resolve" }`.

**Tests.**
- Unit: `NullRouteExecutor` rejects every `execute` with the right `ExecError` variant.
- Integration (hermetic, local): a test spins a loopback `TcpListener`, and `DirectRawTcpExecutor::execute` on a route targeting that listener opens a real connection and the listener observes the bytes. This is the first test in the tree that produces a real network effect (contrast: every existing test uses `LocalFiberExecutor` / `MockDataPlane`).
- Fail-closed: a test that revokes the capability (probe returns `raw_tcp:false`) asserts `execute` returns `CapabilityUnavailable` and opens **no** socket.

**Acceptance criteria.**
- `crates/ssk-netcore` exists, builds, and has a real `RouteExecutor` with at least one executor that produces an observable loopback TCP effect under test, plus a fail-closed `NullRouteExecutor`.
- `ssk-netadmin` remains transport-free (its `Cargo.toml:15-23` dependency set gains no network crate).
- The three reserved `AuditOutcome` variants (`audit.rs:31-42`) now have real producers.

**Non-goals.**
- No remote/arbitrary-host egress, no SOCKS5/HTTP-CONNECT/TLS handshake, no DNS override this run. `Capabilities.tls_tunnel`/`dns_override` are hardwired `false` and documented as future work. The point is a **real, bounded, fail-closed** executor boundary — not a full data plane.

---

### WP3 — Daemon / system integration (replace `MockDataPlane` with a `RouteExecutor`-backed plane; honest status)

**Goal.** Wire `ssk-netcore`'s `RouteExecutor` into the daemon so that "Protected" means a real (bounded) egress capability was probed and honored, and so `GetStatus` stops reporting hardcoded protection constants. Also fix the service-lifecycle defects that make the daemon unsafe to run under a process manager.

**Files / crates.**
- `crates/ssk-daemon/src/mock_dataplane.rs` (to be replaced/demoted; `AlwaysUpMockDataPlane::route_available` → `true` unconditionally, `:17-21`).
- `crates/ssk-daemon/src/supervisor.rs` (`route_available` gate at `:263-268`; hardcoded `dns_protected=false`/`kill_switch=false` at `:251-252,290-291,319-320`; adapter health literal at `:249`; `Supervisor::new` signature at `:44`).
- `crates/ssk-daemon/src/main.rs` (wires `AlwaysUpMockDataPlane` at `:53`; only `ctrl_c` signal at `:71`; lock file at `:22-36,60`).

**New / changed APIs.**
- Change the `Inner.data_plane` abstraction (`supervisor.rs:39`) from `MockDataPlane` to a `Box<dyn RouteExecutor>`. `ActivateProfile` (`supervisor.rs:258-294`) calls `route_executor.probe()` and, for the reference profile, `execute` on a planned route; `Protected` is reached only on a real `Ok(SessionHandle)`.
- `GetStatus` (`supervisor.rs:239-252`) derives `dns_protected` and `kill_switch` from the live executor `Capabilities`/session state, and `adapter_health` from the executor's `probe` result — replacing the literal `"unknown (ssk-netcore not yet integrated)"` string (`:249`).
- `main.rs`: default-wire `NullRouteExecutor` (fail-closed) unless a config/env capability explicitly enables `DirectRawTcpExecutor`. A daemon with no real egress capability reports honest "unprotected, executor=null" — not `Protected`.
- Add SIGTERM handling alongside `ctrl_c` (`main.rs:71`) so a process manager's stop signal triggers graceful shutdown and lock cleanup; remove the stale-lock-on-kill defect (`main.rs:22-36,60` — `create_new` on `sskd.lock` currently blocks restart after SIGTERM/SIGKILL).

**Invariants.**
- **No fabricated protection.** `Protected` with `NullRouteExecutor` is impossible; the state machine must refuse to report protection without a real executor handle. This directly retires the "`sskd` reaches Protected for any profile via hardcoded `true`" finding (`supervisor.rs:263-268` + `mock_dataplane.rs:17-21`).
- **Kill-switch coherence.** The `Deactivate`-while-`FailClosed` guard (`supervisor.rs:297-309`, `KILL_SWITCH_ARMED`) and the reported `kill_switch` status field must agree; today the guard exists but the field is a constant `false` (`:252`) — they are disconnected. After this WP they share one source of truth.

**Failure modes.**
- Executor `probe` fails at activate → daemon enters `FailClosed`, clears profile (mirrors existing `supervisor.rs:269-275`), and `GetStatus` reports the honest reason.
- SIGTERM mid-session → graceful teardown via `RouteExecutor::teardown`, lock removed, no stale `sskd.lock`.

**Tests.**
- Extend `crates/ssk-daemon/tests/round_trip.rs` (real `sskd` over real socket, `:28,46`): with `NullRouteExecutor`, assert activate does NOT reach `Protected` and `GetStatus` reports the honest unprotected reason (this replaces the current test's reliance on the AlwaysUp mock reaching Protected).
- New system test: with `DirectRawTcpExecutor` enabled and a loopback listener, activate reaches `Protected`, `GetStatus.dns_protected`/`kill_switch` reflect real state, deactivate tears down cleanly.
- New test: send SIGTERM to a spawned `sskd`, assert graceful exit and that a subsequent `sskd` start succeeds (no stale lock).
- Keep the supervised-failure watchdog test green (`crates/ssk-daemon/tests/killed_task_transitions.rs:35-53`).

**Acceptance criteria.**
- No `dns_protected`/`kill_switch`/`adapter_health` constant remains in `supervisor.rs`; each is derived from executor state.
- `mock_dataplane.rs` is either deleted or clearly relegated to `#[cfg(test)]` only; the production binary wires a `RouteExecutor` (default `NullRouteExecutor`).
- SIGTERM is handled; stale-lock-on-kill is fixed.

**Non-goals.**
- Cross-restart profile persistence (the `active_profile` in-memory-only finding, `supervisor.rs:45-53`) is not required this run unless trivially co-located with WP6; if deferred, document it.
- Full systemd/launchd packaging is WP8, not here.

---

### WP4 — CLI user-reachable flows (stop `connect` overclaiming; wire real paths honestly)

**Goal.** Make every CLI verb's name and output match its real effect, and give users a real (or cleanly-refused) path to the executor from WP2/WP3. The current `connect` command is the sharpest UX overclaim in the tree.

**Files / crates.**
- `crates/ssk-cli/src/main.rs` — `Connect` clap variant (`:58-65`, args only `valid_fixture/seeded/epoch`, no host/port), `connect_command` (`:510-581`, calls `run_to_outcome(sample_intent, default_pool, LocalFiberExecutor, …)` at `:528-536`, in-memory tensor at `:516-518`, prints `connect: outcome=.. materialized=.. residues=..` at `:576`).
- `default_pool()` (`:1851-1868`), `sample_intent()` (`crates/ssk-runtime/src/lib.rs:581-601`).

**New / changed APIs (CLI surface).**
- **Rename `connect` → `materialize`** (or `simulate-intent`) to match its actual effect (abstract decision-core materialization over a fixture with a local echo executor). Update the output copy from `connect: outcome=..` to explicitly label it a decision-core materialization, not a connection. This is a naming/altitude fix; the code behind it is already honest (`LocalFiberExecutor` doc "fabricates no network liveness").
- **Add a real `connect` verb gated on `ssk-netcore`.** It takes a destination argument, calls the daemon (or an embedded `RouteExecutor`) to `probe` then `execute`, and:
  - on capability present + target allowlisted → performs the real bounded egress and reports the real outcome;
  - on `NullRouteExecutor` / capability absent → exits non-zero with a fail-closed, actionable message (mirroring the existing IPC-absent handling pattern: `IpcError` → exit 12 with "Is `sskd` running?" at `crates/ssk-ipc/src/client.rs:16-24`, `main.rs:194-206`).
  There must be **no** `connect` code path that prints a reassuring "outcome=pass" while touching no traffic.

**Invariants.**
- A verb named `connect` in a privacy/routing product MUST either produce a real (bounded) network effect or refuse fail-closed with a diagnosable reason. The false-reassurance failure mode (user sees `materialized=1`, believes traffic is protected, traffic leaks) is the highest-severity risk in the audit (Verdict F "Catastrophic if shipped green") and must be structurally impossible after this WP.

**Failure modes.**
- Daemon absent → exit 12, "Is `sskd` running?" (existing, keep).
- Executor null / capability absent → distinct non-zero exit with `capability=raw_tcp unavailable` reason.
- Target outside allowlist → refused with `RouteDenied` reason.

**Tests.**
- Update `crates/ssk-cli/tests/ux_snapshots.rs` (runs real `ssk` subprocess) for the renamed `materialize` verb and its new output copy.
- New CLI test: `ssk connect <loopback-target>` against a running `sskd` + `DirectRawTcpExecutor` produces a real observed connection; against `NullRouteExecutor` exits non-zero with the fail-closed reason and opens no socket.

**Acceptance criteria.**
- No CLI verb name implies an effect the code does not perform. `connect` is either backed by a real executor or refuses fail-closed; `materialize` is the honest name for the core-pipeline driver.
- `--json` output for every command carries a machine-readable status/reason.

**Non-goals.**
- `disconnect`/`profile-select` remain served by `deactivate`/`activate --profile` (the audit notes no such named commands exist, `ev:cli` §1); no new profile-selection UX beyond WP6.

---

### WP5 — Diagnostics / audit / replay (make the audit chain non-vacuous; run the TTL sweep; keep replay honest)

**Goal.** Close the three "code exists but is never exercised in a product path" gaps: the daemon never writes its audit ledger, the TTL sweep has zero callers, and replay is honest but must not be relabeled as session replay.

**Files / crates.**
- Daemon audit: `crates/ssk-daemon/src/supervisor.rs` (only `.audit.entries()`/`.audit.verify()` at `:240,404,419,422`; **no `.record()` anywhere**; `Event::AuditAppended` emitted without a persisted entry at `:276-281`; `audit_head` always `None` at `:239-243`; `VerifyAuditChain` vacuous per `crates/ssk-daemon/tests/round_trip.rs:106`).
- TTL sweep: `crates/ssk-tensor/src/lib.rs` (`is_expired` `:211`, `sweep` `:218`, `finalize_expired` `:237-259`; zero non-test callers; residues land in in-memory `ResidueRegister`, `crates/ssk-types/src/lib.rs:730-755`, no persistence/hash-chain). Note the in-code overclaim in the `finalize_expired` doc comment (`ssk-tensor/src/lib.rs:232-234`) calling a non-persisted, non-chained in-memory residue "hash-chained" and "auditable" — fix this comment.
- Stitch-chain verify gap: `StitchTensorEntry` `StorageBackend` (`crates/ssk-tensor/src/lib.rs:63-80`) has `get/iter/head` but **no `verify()`**; verify exists only for the older `TensorEntry` ledger (`:44-48,373-388`).
- Replay: `crates/ssk-replay/src/lib.rs:55` (genuine re-execution — keep, but label honestly).

**New / changed APIs.**
- Daemon: call `AuditLedger::record(...)` (`crates/ssk-netadmin/src/audit.rs:143`) on `ActivateProfile`/`Deactivate`/route decisions so the chain is non-empty; `audit_head` in `GetStatus` reflects the real head; `VerifyAuditChain` now verifies a real chain.
- Tensor: add `StorageBackend::verify()` for `StitchTensorEntry`, symmetric with the `TensorEntry` `verify_chain` (`:373-388`).
- Dissolution: call `DissolutionManager::sweep`/`finalize_expired` from a real driver — the daemon epoch tick or a scheduler tick in `ssk-runtime`; route emitted residues into a **persisted, hash-chained** ledger (reuse `GenericFileLedgerBackend`, `crates/ssk-tensor/src/lib.rs:302-348`) rather than the ephemeral `ResidueRegister`; expose a diagnostic surface (a daemon IPC endpoint or CLI subcommand) so a user can observe swept/finalized dissolutions.

**Invariants.**
- No "verifies green because empty" chains. After this WP, `VerifyAuditChain` on a daemon that has activated at least one profile verifies a chain with ≥1 recorded entry.
- No sweep residue is emitted to a surface that claims persistence/chaining it does not have; the `finalize_expired` doc comment must match the actual sink.

**Failure modes.**
- Ledger append failure (I/O) → surfaced as a real error, not swallowed (the `GenericFileLedgerBackend` append is read-all → push → write-all, `:339-343`; handle write failure fail-closed).
- Chain verify failure → non-zero exit / IPC error with the diverging entry identified.

**Tests.**
- Replace the vacuous `audit_chain_verifies_after_activation` (`supervisor.rs:614-629`) and `round_trip.rs:106` assertions with a test that activates, records, and asserts a **non-empty** verified chain.
- New test: `DissolutionManager::sweep` driven from the daemon tick against a backend holding expired stitches emits residues into the persisted ledger, and the diagnostic surface returns them.
- New test: `StitchTensorEntry` `verify()` detects a tampered entry in a non-empty on-disk chain.
- Keep replay tests green (`crates/ssk-replay/src/lib.rs:110-137`, `crates/ssk-runtime/tests/replay_vectors.rs:30-55`), and update any doc/comment that implies replay reproduces a network session — it reproduces the deterministic core (`LocalFiberExecutor` echo).

**Acceptance criteria.**
- Daemon audit chain is non-vacuous and verified in a real test.
- TTL sweep runs from a real driver, persists residues to a hash-chained ledger, and is user-observable.
- `StitchTensorEntry` has a `verify()`; the `finalize_expired` doc overclaim (`:232-234`) is corrected.

**Non-goals.**
- Full forensic replay of a real network session (blocked by absent capture); replay stays a core-model reproduction and is labeled as such.

---

### WP6 — Config / profile / policy (thread validated config into runtime)

**Goal.** Make the strong, tested config validator actually drive runtime behavior. Today config is `file → parse → migrate → validate → log line → discarded` (`crates/ssk-daemon/src/main.rs:38-53`), and the two "policy" notions never meet: `ssk-config::Policy` is the Ω gate profile (`crates/ssk-config/src/lib.rs:550-576`), while the daemon's routing policy is the hardcoded `reference_policy_engine()` (`crates/ssk-daemon/src/supervisor.rs:112-147`).

**Files / crates.**
- `crates/ssk-daemon/src/main.rs:38-53` (load-then-discard), `crates/ssk-daemon/src/config_load.rs:30-48` (real fail-closed loader).
- `crates/ssk-daemon/src/supervisor.rs:44` (`Supervisor::new` takes only `audit_path` + data plane; no config field in `Inner` `:34-40`), `reference_policy_engine()`/`reference_route_orchestrator()` (`:112-154`), single hardcoded profile (`ListProfiles` at `:325-332`).
- `crates/ssk-config/src/lib.rs` (`AppConfig` `:615-632`; `PolicyEngine`-shaped sections; `schema_json()` hand-written literal at `:846-995`).

**New / changed APIs.**
- `Supervisor::new` gains a validated `AppConfig` parameter; `Inner` gains a config field. `InspectFlow`/`TraceRoute` (`supervisor.rs:333,360`) build their `PolicyEngine`/`RouteOrchestrator` from the config's policy section instead of `reference_policy_engine()`.
- Define the mapping `AppConfig` → `ssk_netadmin::PolicyEngine` rules + `AdapterRegistry` entries + `RouteExecutor` capability flags. This is the "named-profile → policy → adapters → route" model that the audit found absent (`ev:config-policy` §2, currently product-level 1–2).
- On invalid config, enter a real `ConfigInvalid` state (the `DaemonState::ConfigInvalid` variant exists but is never entered, `crates/ssk-ipc/src/state.rs`; `main.rs:43-49` currently only logs and starts with defaults). This retires the "Phase 5" deferral comment at `main.rs:46-47`.

**Invariants.**
- **Config actually changes behavior.** A test must show that two different valid configs produce two different daemon routing decisions — proving config is no longer discarded.
- **Fail-closed on invalid config.** An invalid config must not silently start with defaults and reach `Protected`; it enters `ConfigInvalid` and refuses protection.

**Failure modes.**
- Unsupported version → `UnsupportedVersion` (existing `crates/ssk-config/src/lib.rs:724-730`), surfaced as `ConfigInvalid`, not a silent default.
- Schema-literal drift: add a test that validates the hand-written `schema_json()` (`:846-995`) against the actual `AppConfig` structs (today only a `contains(...)` smoke test at `:1035-1043`), so the schema cannot drift unnoticed.

**Tests.**
- New: two configs → two distinct `InspectFlow`/`TraceRoute` outcomes from a real `sskd`.
- New: invalid config → daemon reaches `ConfigInvalid` and refuses `ActivateProfile`.
- Keep migration tests green (`crates/ssk-config/src/lib.rs:1046-1084`).

**Acceptance criteria.**
- No runtime policy decision path calls `reference_policy_engine()` when a config is present; config drives the `PolicyEngine`/`RouteOrchestrator`/`RouteExecutor` capabilities.
- `ConfigInvalid` is a reachable state; invalid config cannot reach `Protected`.

**Non-goals.**
- Full multi-profile registry beyond wiring the config's profiles; if only the single reference profile is config-driven this run, document the remaining gap (retiring the `ListProfiles` hardcoded singleton at `supervisor.rs:325-332` fully is optional).

---

### WP7 — Conformance / system tests (partition unit / model / integration / system; add a real system tier)

**Goal.** Stop presenting model-property tests as system tests, and add the first genuine system-level test that asserts a real network effect. The audit's core finding on the conformance suite: all four Section-W tests are model-property tests bound to `LocalFiberExecutor` + `LocalOverlay` (`crates/ssk-runtime/tests/conformance.rs:22,60,85,116,127`), and "no test in the tree drives any TCP/UDP/TLS/DNS network effect" (`ev:replay-conformance` §3).

**Files / crates.**
- `crates/ssk-runtime/tests/conformance.rs` (header claims "end-to-end" at `:1-4`; relabel to "end-to-end through the abstract decision core (local-overlay/local-echo only; no network effect)").
- New system-tier tests exercising WP2/WP3 (loopback egress through the real `sskd` + `RouteExecutor`).
- `.github/workflows/ci.yml` job structure (13 jobs at `:11-121`).

**New / changed structure.**
- Introduce explicit test tiers by naming/location convention:
  - **unit** — pure algebra (e.g. `facet_recovers_to_core`, `conformance.rs:42-48`).
  - **model-property** — deterministic-core invariants over `LocalFiberExecutor` (the current Section-W four, relabeled).
  - **integration** — cross-crate in-process (existing `runtime_integration.rs`, `netadmin_integration.rs`).
  - **system** — real binary + real I/O effect (existing `round_trip.rs`, `ipc_status_snapshot.rs` for the control plane; NEW: loopback data-plane egress from WP2/WP3).
- Add a CI job `system_tests` running the new system tier. Fix `breaking_change_guard` (`ci.yml:63-73`) which currently only `echo`es and fails nothing — either make it fail on real breaking changes or mark it advisory in its name.

**Invariants.**
- A test may be labeled "system" only if it drives a real binary and asserts a real system/network effect (socket bytes observed, real audit entry recorded). No model-property test may sit in the system tier.
- The `no_std_core` job must not silently read green when its command fails (WP1 makes the command pass; keep the job).

**Failure modes.**
- Loopback listener unavailable in CI sandbox → the system test must skip explicitly with a logged reason, not pass vacuously.

**Tests / acceptance criteria.**
- The four Section-W tests are relabeled model-property; the "system" tier exists and contains at least one real-network-effect test.
- CI has a distinct `system_tests` job; `breaking_change_guard` no longer masquerades as a gate.

**Non-goals.**
- Cross-platform (macOS/Windows) matrix; MSRV/nightly matrix. Single `ubuntu-latest` runner stays this run (`ci.yml:12`), documented as a coverage limit.

---

### WP8 — Packaging / docs / doctor (ship binaries; correct the doc maturity claims)

**Goal.** Make the release artifact runnable, add minimal service integration, and reconcile every overclaiming doc line against the evidence. Doctor already does real local checks; extend it to probe the new executor capability.

**Files / crates.**
- `.github/workflows/release.yml:19-20` (builds `--release` then tars only `crates`, `Cargo.toml`, `README.md`, `docs` — the compiled `target/release/ssk`,`sskd` are discarded) vs claim `README.md:381` ("packages platform binaries").
- Docs to correct: `README.md:3,32,39,108,283-292`; `docs/NETADMIN_SPEC.md:5-8,15-25,190-196,240`; `docs/COMPLETION_CHECKLIST.md:30,33`; `docs/OMEGA_CORE_CONFORMANCE_SPEC.md:39,256,258`; `SECURITY.md:17,47-49`.
- `crates/ssk-cli/src/main.rs` doctor (`doctor_command:717-804`, real checks: clock `:1071`, `/dev/urandom` `:1098`, cwd `:1120`, `.ssk` write-perm `:1137`).

**New / changed work.**
- `release.yml`: include the built `ssk`/`sskd` binaries in the release artifact (and/or per-target binaries). At minimum, the tar must contain a runnable binary, not only source.
- Add a minimal systemd unit file (`.service`) and SIGTERM handling reference (SIGTERM fix lands in WP3); document `SSK_STATE_DIR`/`SSK_CONFIG_PATH` and the single-instance lock (`crates/ssk-ipc/src/paths.rs:10-20`, `main.rs:38,55`).
- `doctor`: add a capability probe (`RouteExecutor::probe`) so `ssk doctor` reports whether real egress is available and, if not, the honest reason — consistent with WP2/WP3 fail-closed reasons.
- **Doc reconciliation (each line quoted-and-corrected):**
  - `README.md:3` "Production-oriented … runtime" → honest maturity statement: "deterministic decision/audit/planning core + local IPC daemon; bounded local egress via `ssk-netcore`; full data plane (remote adapters, capture) not yet implemented."
  - `README.md:39` / `NETADMIN_SPEC.md:5-8` "traffic routing without third-party proxy software" / "replaces Proxifier" → scope to "policy-driven route **planning** + bounded local egress execution; remote adapter transport not yet implemented."
  - `README.md:283-292` adapter table "`DirectAdapter` → Raw TCP" etc. → mark which adapters have a real executor (Direct, loopback-scoped) and which are descriptor-only (SOCKS5/HTTP-CONNECT/TLS/DNS), consistent with `adapter.rs:37-40`.
  - `docs/OMEGA_CORE_CONFORMANCE_SPEC.md:256` SSK-Ω-7 ⚠️ → keep ⚠️ but update the pointer: `ssk-netcore` now exists with a bounded executor; remote adapters/health probing still out of scope. Correct the `:39` summary so it no longer claims all rungs met.
  - `docs/OMEGA_CORE_CONFORMANCE_SPEC.md:258` SSK-Ω-9 "✅ met" → downgrade to reflect WP5 reality (TTL sweep now driven, audit chain now non-vacuous) or, for any sub-clause still unmet, mark "⚠️ partial" with the specific gap.
  - `SECURITY.md:17` "real ed25519 signing available" → clarify shipped default is a symmetric Blake3 keyed-MAC (`attestation.rs:86-132`), integrity for shared-secret holders, not third-party-verifiable signatures.
  - `SECURITY.md:47-49` "zero-key constructors compile-time restricted to test builds" → correct against `ssk-interop/src/lib.rs:53-57` (unrestricted `pub` constructors per `docs/DESKTOP_CLIENT_ARCHITECTURE.md:199`) or restrict the constructors to match the claim.

**Invariants.**
- Every "done"/"met"/"✅" marker in the docs must have a corresponding acceptance test cited, or be downgraded to "⚠️ partial" / "planned" with the gap named.
- The release artifact must contain a binary a user can run.

**Tests / acceptance criteria.**
- A release-artifact smoke check: extract the artifact, run `ssk --version` / `sskd --version` from it.
- `doctor` reports executor capability honestly (real when `DirectRawTcpExecutor` enabled, fail-closed reason otherwise).
- A docs-vs-code reconciliation table (see §5) exists and every row is either "closed" or "accepted non-goal."

**Non-goals.**
- macOS/Windows installers, `.deb`/PKGBUILD, auto-updater, GUI. Documented as future work.

---

## 4. Definition of Done (binding gate for the next run)

The next run MUST NOT re-claim "done" (in any language, including "produktreif", "100% fertig", "production-ready") for the product until **every** item below is satisfied. Each item names its evidence anchor so it can be checked mechanically.

1. **Product contract fully mapped to the repo.** A table (§5) maps each of the 12 promised capabilities (`README.md`/`NETADMIN_SPEC.md`, enumerated in `ev:product-contract-docs` §1b) to its real code status and its acceptance test (or an explicit "accepted non-goal this run"). No promised capability is left unmapped.

2. **All release blockers closed or explicitly accepted as real non-goals.** The two hard falsifiers are closed: (a) `cargo check -p ssk-core --no-default-features` exits 0 (WP1); (b) SSK-Ω-7 is either advanced by a real bounded executor (WP2/WP3) or its "✅ all met" summary at `docs/OMEGA_CORE_CONFORMANCE_SPEC.md:39` is corrected to match the ⚠️ row at `:256`.

3. **No mock sold as real.** No production code path returns a hardcoded protection/liveness value presented as real: `AlwaysUpMockDataPlane` (`mock_dataplane.rs:17-21`) is removed from the production binary; `GetStatus` `dns_protected`/`kill_switch`/`adapter_health` (`supervisor.rs:249-252`) are executor-derived; the `LocalFiberExecutor` echo is never described as a network effect in user-facing output.

4. **CLI/daemon/netcore path really executable or cleanly blocked as unimplemented.** `ssk connect` either performs a real bounded egress or exits non-zero with a fail-closed, actionable reason (WP4). No verb prints a reassuring success while touching no traffic (retires Verdict F's catastrophic false-reassurance mode).

5. **User-visible error diagnosis present.** Every failure mode in WP2–WP6 surfaces a machine-readable reason and a non-zero exit / IPC error, following the existing pattern (`IpcError` → exit 12 with next-step text, `crates/ssk-ipc/src/client.rs:16-24`, `main.rs:194-206`).

6. **Fail-closed tested for missing permissions / adapters / network.** Tests assert that with no socket capability, no real adapter, or a null executor, the system refuses protection and opens no socket (WP2 fail-closed test; WP3 `NullRouteExecutor` round-trip test).

7. **Conformance suite separates unit / integration / system.** The four Section-W tests are labeled model-property (`conformance.rs` relabel); at least one real-network-effect system test exists; CI runs a distinct system tier (WP7). No model test is presented as a system test.

8. **Docs state honest maturity.** Every "done"/"met"/"✅" marker is backed by a cited acceptance test or downgraded to "⚠️ partial"/"planned" with the named gap (WP8). The docs-vs-code reconciliation table (§5) has no open, uncorrected overclaim.

9. **No "produktreif"/"production-ready" without real system acceptance tests.** The product may be described as production-ready only after a system acceptance test drives real traffic through a real `RouteExecutor`, asserts a real network effect, asserts a real audit-ledger append, and asserts kill-switch teardown — for the specific capabilities claimed. Absent that, the honest ceiling is: artifact-level 4 for the decision/audit/planning core; product-capability level 2–3 for the bounded local egress delivered this run; and unimplemented for remote adapters, capture, DNS override, TLS tunnel, and the desktop GUI.

**Forbidden framings (do not use in code, commits, or docs):** claiming a rung "met" without an evidence citation; describing `LocalFiberExecutor` output as network liveness; marking remote-adapter transport "functional"; asserting "cryptographically-audited" for the daemon audit path while it records nothing; calling the symmetric Blake3 keyed-MAC "signed capability attestation"; and any "100% / fully done / production-ready" phrasing for a capability lacking a real system acceptance test.

---

## 5. Docs-vs-code reconciliation table (to be filled and kept current)

Each row must end this run as **Closed** (code now matches doc) or **Accepted non-goal** (doc corrected to state the gap). No row may remain **Open**.

| # | Doc claim (quoted) | Code reality (file:line) | WP | Required end-state |
|---|---|---|---|---|
| O-1 | `README.md:3` "Production-oriented … runtime" | Decision/audit/planning core; only real I/O is a local Unix socket + `/dev/urandom` + file ledger; `DESKTOP_CLIENT_ARCHITECTURE.md:33-38,114-118` | WP8 | Doc downgraded to honest maturity |
| O-2 | `README.md:39`, `NETADMIN_SPEC.md:5-8` "traffic routing without third-party proxy software / Proxifier replacement" | Routes planned, never executed; `route.rs:60` "ready for dispatch" but nothing dispatches; `ssk-netcore` absent | WP2/WP3/WP8 | Bounded local egress real; remote scoped as planned |
| O-3 | `README.md:283-292` "`DirectAdapter` → Raw TCP", TLS tunnel, DNS override | `trait DataPlaneAdapter { adapter_id; describe }`, no `connect` (`adapter.rs:37-40`); descriptor-only (`adapter.rs:5-9`) | WP2/WP8 | Direct has real (loopback) executor; others labeled descriptor-only |
| O-4 | `NETADMIN_SPEC.md:240` "all adapter types functional" | Planner only; `RouteExecutor` newly added for Direct/loopback | WP2/WP8 | Claim scoped to the one real executor |
| O-5 | `README.md:39,116`, `COMPLETION_CHECKLIST.md:30` "signed capability attestation" | Symmetric Blake3 keyed-MAC default (`attestation.rs:86-132`; honesty `DESKTOP_CLIENT_ARCHITECTURE.md:108-110`) | WP8 | Doc corrected to "keyed-MAC, not signing" |
| O-6 | `SECURITY.md:47-49` "zero-key constructors restricted to test builds" | Unrestricted `pub` constructors (`ssk-interop/src/lib.rs:53-57`; `DESKTOP_CLIENT_ARCHITECTURE.md:199`) | WP8 | Restrict constructors or correct doc |
| O-7 | `README.md:397` desktop GUI / dashboard | No Tauri/GUI/updater (`DESKTOP_CLIENT_ARCHITECTURE.md:201`) | WP8 | Marked planned / out of scope |
| O-8 | `README.md:102` "`ssk-core` no_std … verified in CI" | `cargo check -p ssk-core --no-default-features` fails at `connection.rs:55,78,87` | WP1 | Build fixed; CI green |
| O-9 | `OMEGA_CORE_CONFORMANCE_SPEC.md:39` "SSK-Ω-0 through 9 all met" | Contradicted by `:256` SSK-Ω-7 ⚠️; SSK-Ω-9 `:258` overclaims (TTL sweep zero callers, audit vacuous) | WP3/WP5/WP8 | Summary corrected to match per-rung reality |
| O-10 | `release.yml`/`README.md:381` "packages platform binaries" | Tars only source; binaries discarded (`release.yml:19-20`) | WP8 | Release ships runnable binaries |
| O-11 | `OMEGA_CORE_CONFORMANCE_SPEC.md:258` SSK-Ω-9 "✅ met" dissolution/ledger | TTL sweep no callers (`ssk-tensor/src/lib.rs:211,218,237-259`); daemon never records audit (`supervisor.rs`, no `.record()`) | WP5 | Sweep driven + audit non-vacuous, or rung marked ⚠️ partial |

---

## 6. Cross-cutting engineering constraints

- **Keep the honest layers honest.** The daemon's live status (`dns_protected=false`, `ListRecentFlows=[]`, "ssk-netcore not yet integrated") is currently truthful; do not "improve" it into a fabricated `true`. Every status field must remain derivable from real state after WP3.
- **Fail-closed everywhere new I/O appears.** The existing fail-closed properties are model-internal (no tensor mutation without a passing gate, `crates/ssk-runtime/src/lib.rs:251-264`; typestate `materialize` only on `GatePassed`, `connection.rs:201-217`). WP2/WP3 must extend fail-closed to the transport layer, where today it has "no enforcement teeth" (`ev:netadmin` §4).
- **`#![forbid(unsafe_code)]` stays.** Workspace-wide via `Cargo.toml:56-57`; `ssk-netcore` must honor it (use safe `tokio`/`std::net`, no raw FFI).
- **Determinism boundary.** The deterministic core (`ssk-scheduler`, `run_to_outcome`) must remain deterministic and replayable (`run_to_outcome_is_deterministic`, `crates/ssk-runtime/src/lib.rs:922-953`). Real network effects live behind the `RouteExecutor`/`FiberExecutor` trait boundary (`crates/ssk-runtime/src/lib.rs:179-181`) so they do not contaminate the deterministic core or its replay guarantee.
- **Supply-chain hygiene stays.** `cargo audit`/`cargo deny` (`ci.yml:107-121`, `deny.toml:12-42`), SHA-pinned actions, Dependabot — any new `ssk-netcore` dependency (e.g. `tokio`) must pass `cargo deny` and be added to the allow-list deliberately.

---

## 7. Summary of the honest starting maturity (for the run's own baseline)

| Capability | Artifact level | Product-capability level | Anchor |
|---|---|---|---|
| Deterministic decision core (`run_to_outcome`) | 4 | 2 | `crates/ssk-runtime/src/lib.rs:230-314`; `LocalFiberExecutor` echo `:189-213` |
| 12-gate fail-closed vector | 4 | 2 | `crates/ssk-gates/src/lib.rs:381-417` |
| Connection typestate | 4 | 2 | `crates/ssk-core/src/connection.rs:201-217`; breaks no_std `:55,78,87` |
| Locator BFS / `select_egress` | 3–4 | 1 (not user-reachable) | `crates/ssk-locator/src/lib.rs:159-227`; empty graph `crates/ssk-runtime/src/lib.rs:348-352` |
| Tensor append+chain (in-memory) | 4 | 2 | `crates/ssk-tensor/src/lib.rs:153,170-184`; no `StitchTensorEntry` verify `:63-80` |
| TTL sweep / dissolution | 3 | 1 | `crates/ssk-tensor/src/lib.rs:211,218,237-259` (zero product callers) |
| Replay engine | 4 | 2 (model, not session) | `crates/ssk-replay/src/lib.rs:55` |
| Unix-socket IPC + state machine | 5 | 5 (local control plane only) | `crates/ssk-ipc/src/server.rs:86-100`; `round_trip.rs:28,46` |
| Daemon data plane / Protected | 2–3 (mock) | 2 | `crates/ssk-daemon/src/mock_dataplane.rs:17-21`; `main.rs:53` |
| Daemon persisted audit (as used) | 4 artifact / not integrated | 1 | `supervisor.rs` no `.record()`; vacuous verify `round_trip.rs:106` |
| Config validator | 4 | 0–1 (parsed then discarded) | `crates/ssk-config/src/lib.rs:724-762`; discarded `main.rs:38-53` |
| netadmin policy/route planner | 4 | 2 (plans, cannot execute) | `policy.rs:138-157`, `route.rs:127-180`; adapters descriptor-only `adapter.rs:37-40` |
| Data-plane transport (remote) | 0 | 0 (`ssk-netcore` absent) | `ls crates/ssk-netcore` → absent; SSK-Ω-7 ⚠️ `spec:256` |
| Traffic capture / ingress | 0 | 0 (`ssk-capture` absent) | `ls crates/ssk-capture` → absent; `ListRecentFlows=[]` `supervisor.rs:397-401` |
| Desktop GUI / updater / packaging | 0–1 | 0–1 | `DESKTOP_CLIENT_ARCHITECTURE.md:201`; `release.yml:19-20` ships source |

This table is the run's honest floor. The Definition of Done (§4) is the run's ceiling gate. The gap between them is the work.