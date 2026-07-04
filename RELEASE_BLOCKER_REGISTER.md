# RELEASE_BLOCKER_REGISTER.md

> **Status:** This register is the hard gap list for the SSK-Ω / kaleidoscorp.io workspace on branch `claude/rust-arch-audit-gaps-immuk1` as of 2026-07-04. It is deliberately unsentimental. Every entry cites `file:line` evidence. Where the code is honestly incomplete, that is stated and the in-code honesty marker is quoted. Where documentation overclaims, the doc line is quoted and contrasted against code.
>
> **One-line reconciliation up front:** The repository is a real, deterministic, well-tested **decision / audit / planning core** plus a **local Unix-socket daemon skeleton** — maturity **level 4 as a code artifact**. It is **not** a working network/privacy product: there is no data plane. The single most important fact in this register is that **README and the marketing docs present a shipping traffic-protection / routing product while no code moves a byte** (see **RB-A1**). Two independent hard falsifiers of any "done / 100% produktreif" claim are recorded: **RB-A1** (no data plane; SSKΩ-7 self-graded ⚠️ and deferred to an absent crate) and **RB-A2** (the advertised `no_std` guarantee does not compile in-tree).

---

## Severity legend

| Severity | Meaning |
|---|---|
| **Critical** | Falsifies a headline product claim, or is a user-facing safety hazard (false sense of protection). Blocks any release that implies the product contract. |
| **High** | Blocks a release that claims the specific capability; core capability is absent or unverified. |
| **Medium** | Real gap that undermines a claim's completeness or an operator's trust; must be scoped-down in docs if not fixed. |
| **Low / Non-blocker** | Hygiene, hardening, or scope items that do not block an honestly-scoped release. |

## Maturity ladder (0–7) used throughout

`0` absent · `1` documented/typed only · `2` API/type model · `3` mock/unit-tested in isolation · `4` locally executable, real internal collaborators, tested · `5` real system/network effect · `6` user-reachable delivered capability · `7` hardened/operated product.

The core artifact is repeatedly **level 4**. As a *network/privacy product capability* the same subsystems sit at **level 1–2**. This register never conflates the two.

---

# A. Release Blockers

## RB-A1 — The product has no data plane; README/docs present traffic protection & routing as delivered

**Severity: Critical.** *(Also an Architecture Blocker — see cross-reference in Section B — and a Documentation Blocker — see Section F. It is filed here because it is the primary reason the product cannot ship under its stated contract.)*

**Description.** The product contract promises "policy-driven, cryptographically-audited **traffic routing without third-party proxy software**" — a Proxifier replacement with Raw-TCP / SOCKS5 / HTTP-CONNECT / TLS / DNS egress, a kill-switch, and DNS protection. No such capability exists. Routes are *planned and then discarded*; adapters are *descriptor structs with no transport*; the daemon reaches `Protected` through a hardcoded mock; and the responsible transport crate does not exist in the tree.

**Why it is a gap.** For a privacy/anti-surveillance tool this is the worst failure class: a user who runs `sskd`, activates a profile, and sees `state=Protected` would reasonably believe their traffic is now routed/protected. In reality **zero bytes are intercepted or routed** — every connection egresses normally and unprotected, while the UI affirmatively reassures. A false "Protected" indicator is more dangerous than an honest error.

**Affected files/crates (file:line).**
- Adapters are descriptor-only: `crates/ssk-netadmin/src/adapter.rs:37-40` — `trait DataPlaneAdapter { fn adapter_id(&self)->&str; fn describe(&self)->AdapterDescriptor; }` (no `connect`, no `send`, no `open`). Module doc `adapter.rs:3-9`: *"Adapters are **descriptor-only** … The actual transport is the responsibility of the caller."*
- `DirectAdapter::describe()` returns `{ kind: Direct, address: "", port: 0 }` — a label, not a socket: `crates/ssk-netadmin/src/adapter.rs:63-71`.
- No network dependency exists in the crate at all: `crates/ssk-netadmin/Cargo.toml:15-23` (no `tokio`, no `std::net`-based crate, no `rustls`/`native_tls`, no `hyper`/`reqwest`, no `socket2`, no DNS resolver).
- Routes are planned then dropped: `crates/ssk-netadmin/src/route.rs:113-180` (`RouteOrchestrator::plan` builds a `RouteCandidate`; nothing consumes it). Reserved-but-never-produced audit outcomes document the gap: `crates/ssk-netadmin/src/audit.rs:31-42` (`AdapterUnreachable`, `KillSwitchBlocked`, `FallbackDispatched` — comment: *"Not yet produced by any code path until the `ssk-netcore` data-plane runtime ships (Phase 3)."*).
- Daemon data plane is a mock wired into the production binary: `crates/ssk-daemon/src/mock_dataplane.rs:17-21` (`AlwaysUpMockDataPlane::route_available` returns `true` unconditionally, `_profile_id` ignored); wired at `crates/ssk-daemon/src/main.rs:53`. `Protected` is reached solely via this mock: `crates/ssk-daemon/src/supervisor.rs:263-268`.
- Live status is hardcoded (this part is honest — see RB-F1): `crates/ssk-daemon/src/supervisor.rs:251` (`dns_protected: false`), `:252` (`kill_switch: false`), `:249` (adapter health = `"unknown (ssk-netcore not yet integrated)"`), `:397-401` (`ListRecentFlows` returns `vec![]`, comment *"Never fabricate flows."*).
- Responsible transport crate is **absent**: `crates/ssk-netcore` does not exist; `crates/ssk-capture` does not exist (verified by directory listing).

**Affected spec location.**
- Product contract: `README.md:39` ("traffic routing without third-party proxy software"), `README.md:3` ("Production-oriented, pure Rust runtime"), `docs/NETADMIN_SPEC.md:5-8` ("replaces … Proxifier and equivalents"), `docs/NETADMIN_SPEC.md:240` ("all adapter types **functional**, CLI-operable").
- The rung whose own definition requires this and which is **self-graded ⚠️/not met**: `docs/OMEGA_CORE_CONFORMANCE_SPEC.md:256` (SSKΩ-7: *"real egress adapters/health probing … remain out of scope … real network I/O stays the Desktop track's `ssk-netcore` responsibility"*). This directly contradicts the summary self-grade at `docs/OMEGA_CORE_CONFORMANCE_SPEC.md:39` ("SSKΩ-0 through SSKΩ-9 are all met").
- The repo's own internal honesty audit already documents this: `docs/DESKTOP_CLIENT_ARCHITECTURE.md:114-118` (*"the entire live data plane, daemon, IPC, OS-integration, persistence, and signing stack must be built new"*), `:54-56` (*"`RouteOrchestrator::plan()` … returns a `RouteCandidate` struct and stops"*), `docs/NETADMIN_SPEC.md:185-188` (*"A runtime `connect()` ships in **Phase 3** as `ssk-netcore::AdapterRuntime::connect`"* — i.e. does not exist yet).

**Concrete target decision.** Do **not** ship under the current product contract. Choose one:
1. **Re-scope the release** to what exists: "a deterministic decision/audit/planning core plus a local IPC daemon skeleton; data plane not implemented." (Fastest, honest; unblocks a level-4 artifact release.)
2. **Build the data plane** (`ssk-netcore`, Phase 3) and `ssk-capture` (Phase 4) and integrate them before making any traffic-protection claim.

**Minimal clean fix (for option 1, to unblock an honest release now).** Rewrite `README.md:3,32,39,108`, `docs/NETADMIN_SPEC.md:5-8,240`, and `docs/COMPLETION_CHECKLIST.md:33` to describe planning/decision capability only, and change the SSKΩ summary at `docs/OMEGA_CORE_CONFORMANCE_SPEC.md:39` to match its own `:256` ⚠️ row. Align the marketing prose to the daemon's already-honest live status.

**Minimal clean fix (for option 2, the real product).** Create `crates/ssk-netcore` implementing `DataPlaneAdapter::connect` for Direct (raw TCP) / SOCKS5 / HTTP-CONNECT / TLS / DNS with real transport and health probing; replace `crates/ssk-daemon/src/mock_dataplane.rs` with a `RouteExecutor`-backed data plane; make `GetStatus` report real `dns_protected`/`kill_switch` and `ListRecentFlows` from `ssk-capture` ingress.

**Acceptance criterion.** Either (1) no doc claims a network effect the code cannot perform, and the SSKΩ summary matches its per-rung grades; **or** (2) a running `sskd`, on activate, opens a real egress via a real adapter, reports `dns_protected`/`kill_switch` truthfully, populates `ListRecentFlows` from real captured traffic, and honors kill-switch teardown on deactivate/exit.

**Required future test evidence.** An automated end-to-end test that drives a **real socket egress** through a real adapter and asserts (a) a real network effect against a hermetic loopback TCP/DNS endpoint, (b) a real audit-ledger append recording the decision, and (c) kill-switch teardown blocking egress when protection cannot be guaranteed. No such test exists anywhere in `crates/*/tests` today (confirmed: every integration test reaches `Protected`/status through `AlwaysUpMockDataPlane` or `LocalFiberExecutor`).

---

## RB-A2 — `ssk-core` does not compile under `--no-default-features`, breaking the advertised, CI-"verified" `no_std` guarantee

**Severity: High.**

**Description.** README advertises `ssk-core` as `no_std`-friendly and "verified in CI via `cargo check --no-default-features`." The command fails to compile in this tree.

**Why it is a gap.** A documented, CI-claimed guarantee is a concrete counterexample to "all green / done." `ssk-core/src/connection.rs` uses bare `Vec` with no `use alloc::vec::Vec;`, so the no-default path yields hard compile errors.

**Affected files/crates (file:line).**
- `crates/ssk-core/src/connection.rs:55` (`-> Result<Vec<StitchId>, FaultKind>`), `:78` (`stitches: Vec<StitchId>`), `:87` (`Vec::new()`) — the only import is `use core::marker::PhantomData` at `:18`; no `alloc` import.
- Reproduced: `cargo check -p ssk-core --no-default-features` → exit 101, three errors `E0433`/`E0425` ("cannot find type `Vec`").
- Feature wiring makes this a real, exercised configuration: `crates/ssk-core/Cargo.toml:7-9` (`default = ["std"]`, `std = ["ssk-types/std"]`).
- The CI job that is supposed to catch it: `.github/workflows/ci.yml:75-81` (`no_std_core`: `cargo check -p ssk-core --no-default-features`). As written the command fails; whether the job has gone red depends on whether this branch's Actions have run.

**Affected spec location.** `README.md:102` ("`ssk-core` … `no_std`-friendly and **verified in CI**"), `README.md:342-343`, `README.md:371` (lists the `no_std_core` CI job).

**Concrete target decision.** Restore the guarantee (preferred) or delete the claim.

**Minimal clean fix.** Add `#[cfg(not(feature = "std"))] extern crate alloc;` and `use alloc::vec::Vec;` to `crates/ssk-core/src/connection.rs`.

**Acceptance criterion.** `cargo check -p ssk-core --no-default-features` exits 0, and the `no_std_core` job is green on this branch.

**Required future test evidence.** Green `no_std_core` CI run on this branch (the job already exists; it must actually pass, not merely be configured).

---

## RB-A3 — SSKΩ ladder summary self-contradicts; "all met" is false by the spec's own text

**Severity: High.** *(Documentation-rooted; filed as a release blocker because it is the summary line most likely to be quoted as "done".)*

**Description.** `docs/OMEGA_CORE_CONFORMANCE_SPEC.md:39` claims SSKΩ-0 through SSKΩ-9 are all met. The same document grades SSKΩ-7 as **⚠️** at `:258`… correction, at `:256`, and defers it to an absent crate.

**Why it is a gap.** The summary is internally falsified. Independent re-evaluation (below) grades **SSKΩ-7 = FAIL**, **SSKΩ-5 = PARTIAL**, **SSKΩ-9 = PARTIAL**, **SSKΩ-2 = PARTIAL**.

**Affected spec location & re-graded status.**

| Rung | Spec line | Self-grade | Honest re-grade | Basis |
|---|---|---|---|---|
| SSKΩ-0 | `:249` | ✅ | **PASS (default) / broken no_std** | see RB-A2 |
| SSKΩ-1 | `:250` | ✅ | **PASS (core model)** | deterministic scheduler real & tested (`crates/ssk-scheduler/src/lib.rs:40-87`) |
| SSKΩ-2 | `:251` | ✅ | **PARTIAL** | "locator-reality check" is a 3-field predicate, no liveness (`crates/ssk-gates/src/pch.rs:195-197`); `MirrorOrbit::derive` orientation is a hardcoded placeholder (`crates/ssk-core/src/lib.rs:87-88`) — see RB-B4 |
| SSKΩ-3 | `:252` | ✅ | **PASS (core model)** | real BCIK crossing + Blake3 trace (`crates/ssk-runtime/src/lib.rs:268-283,136-159`) |
| SSKΩ-4 | `:253` | ✅ | **PASS (with caveats)** | default-deny real; always-pass Protocol axis + Hold-masks-Reject — see RB-C4, RB-B3 |
| SSKΩ-5 | `:254` | ✅ | **PARTIAL** | in-memory only; no stitch-chain verify; daemon never writes audit — see RB-E1, RB-B2 |
| SSKΩ-6 | `:255` | ✅ | **PASS (core model)** | genuine re-execution replay (`crates/ssk-replay/src/lib.rs:55`) |
| SSKΩ-7 | `:256` | ⚠️ | **FAIL** | no data plane — see RB-A1 |
| SSKΩ-8 | `:257` | ✅ | **PASS (model testbed)** | in-process metrics/adversary sim over abstract candidates |
| SSKΩ-9 | `:258` | ✅ | **PARTIAL** | TTL sweep unwired, config discarded, release ships source — see RB-D2, RB-B1, RB-G1 |

**Concrete target decision.** Replace the "all met" summary with the per-rung honest grades above; keep the ⚠️/FAIL/PARTIAL markers visible.

**Minimal clean fix.** Edit `docs/OMEGA_CORE_CONFORMANCE_SPEC.md:39` to state "SSKΩ-0,1,3,4,6,8 met as core-model rungs; SSKΩ-2,5,9 partial; SSKΩ-7 not met (deferred to absent `ssk-netcore`)."

**Acceptance criterion.** No summary line asserts a rung as met that a per-rung row grades ⚠️/partial.

**Required future test evidence.** N/A (documentation reconciliation); indirectly gated by RB-A1/RB-E1/RB-D2 acceptance.

---

# B. Architecture Blockers

## RB-B1 — Validated config is parsed then discarded; it drives no runtime behavior

**Severity: High.**

**Description.** The 12-section `AppConfig` is loaded, migrated, and validated (a genuine level-4 validator) — then dropped. The supervisor takes no config; every runtime policy/route decision uses a hardcoded reference ruleset.

**Why it is a gap.** `privacy.adversary_model`, `locator_plane.allowed_types`, `bcik.closure_threshold`, gate order, ledger flags, etc. have **zero effect** on daemon behavior. An invalid config produces only a log line and the daemon still starts and can reach `Protected`.

**Affected files/crates (file:line).**
- Load-then-discard: `crates/ssk-daemon/src/main.rs:38-50` (on success, only `tracing::info!(… "config loaded")`; the `loaded` value drops at the match arm end; comment `:46-47`: *"Wiring this into a live `config_invalid` state is Phase 5 work"*).
- Supervisor takes no config: `crates/ssk-daemon/src/supervisor.rs:44` (`Supervisor::new(audit_path, data_plane)`); `Inner` fields `:34-40` (no config field).
- Hardcoded rulesets used instead: `crates/ssk-daemon/src/supervisor.rs:112-147` (`reference_policy_engine`, two literal rules), `:149-154` (`reference_route_orchestrator`, one literal adapter); used at `:333` (`InspectFlow`), `:360-361` (`TraceRoute`).
- The two "policy" notions never meet: `ssk-config::Policy` is the Ω gate profile (`crates/ssk-config/src/lib.rs:550-576`); the daemon's routing policy is `ssk_netadmin::PolicyEngine`.

**Affected spec location.** `README.md:204-223,294-299` (versioned profiles/policy config), `docs/OMEGA_CORE_CONFORMANCE_SPEC.md:258` (SSKΩ-9 "documented limits / config"). Honesty marker already in code: comment at `crates/ssk-daemon/src/supervisor.rs:114-116` ("built-in demo ruleset until Phase 5's config-driven profile model ships").

**Concrete target decision.** Thread the validated `AppConfig` into `Supervisor` and `ssk-netadmin`, retiring the hardcoded reference engines; and on validation failure enter a real `ConfigInvalid` state (the wire variant already exists but is never entered — see RB-B5).

**Minimal clean fix.** Add a `config: AppConfig` field to `Supervisor::Inner`, pass `loaded.config` through `Supervisor::new`, and build the `PolicyEngine`/`RouteOrchestrator` from it instead of the `reference_*` constructors.

**Acceptance criterion.** Changing a policy rule / adapter / gate-order in the config file measurably changes a `flow-inspect`/`route-trace` result; an invalid config drives the daemon to `ConfigInvalid`, not to defaults.

**Required future test evidence.** A test that loads two different valid configs and asserts different `PolicyEngine::evaluate` outcomes for the same flow; a test that an invalid config yields `ConfigInvalid` state rather than a running daemon.

---

## RB-B2 — Daemon never writes its audit ledger; `VerifyAuditChain` verifies an empty chain

**Severity: High.**

**Description.** The persisted, hash-chained audit ledger backend is real infrastructure, but the daemon only ever **reads** it. No request path calls `.record()`. Therefore `audit.json` is never created, `audit_head` is always `None`, and `VerifyAuditChain` trivially returns `ok:true` on a zero-entry chain — making "cryptographically-audited" undemonstrated at runtime.

**Why it is a gap.** The README claim of a cryptographically-audited product is not exercised by any daemon path; the round-trip test's `assert!(v.ok)` is vacuous.

**Affected files/crates (file:line).**
- No `.record()` anywhere in the supervisor; only `.audit.entries()` (`crates/ssk-daemon/src/supervisor.rs:240,404,422`) and `.audit.verify()` (`:419`).
- `audit_head` always `None`: `crates/ssk-daemon/src/supervisor.rs:239-243`.
- `ActivateProfile` bumps an in-memory counter and emits a *named* event only: `crates/ssk-daemon/src/supervisor.rs:276-281` (`Event::AuditAppended`, no persisted entry).
- Backend is real and works: `crates/ssk-tensor/src/lib.rs:329-347` (`GenericFileLedgerBackend`), `crates/ssk-netadmin/src/audit.rs:143` (`AuditLedger::record` exists but is not called by the daemon).
- Vacuous verification asserted green: `crates/ssk-daemon/tests/round_trip.rs:106`; `audit_chain_verifies_after_activation` (`crates/ssk-daemon/src/supervisor.rs:614-629`).

**Affected spec location.** `README.md:39,301` ("cryptographically-audited"), `docs/NETADMIN_SPEC.md:200-221`, `docs/OMEGA_CORE_CONFORMANCE_SPEC.md:254` (SSKΩ-5 "audit").

**Concrete target decision.** Make the daemon `record()` a hash-chained entry on every state-affecting request (activate/deactivate/route decision/fail-closed transition).

**Minimal clean fix.** In the `ActivateProfile`/`Deactivate`/fail-closed transitions in `supervisor.rs`, call `AuditLedger::record(...)` before emitting `Event::AuditAppended`, and surface the real `audit_head` in `GetStatus`.

**Acceptance criterion.** After an activate, `audit.json` exists, `GetStatus.audit_head` is `Some(_)`, and `VerifyAuditChain` verifies a **non-empty** chain of real recorded actions.

**Required future test evidence.** Replace the vacuous assertion in `crates/ssk-daemon/tests/round_trip.rs:106` with an assertion that the verified chain has ≥1 entry corresponding to the activation just performed.

---

## RB-B3 — Route/decision typestate & path-selection are dead outside the test harness (no user-reachable driver)

**Severity: Medium.**

**Description.** Two genuinely-built core mechanisms have **zero non-test callers**: the `Connection<S>` compile-time typestate, and the hypercube-bound path selector `select_egress`/`HypercubePathCheck`. The CLI `connect` runs `run_to_outcome` via an inline pipeline that bypasses both; the daemon references neither.

**Why it is a gap.** These are real level-4 artifacts presented as delivered machinery, but nothing a user can invoke exercises them, and `select_egress` deliberately empties the routing graph so its tested multi-hop BFS degenerates to zero-hop.

**Affected files/crates (file:line).**
- `Connection<S>` transitions real & tested but only test-reachable: `crates/ssk-core/src/connection.rs:143-217`; grep across `ssk-cli`/`ssk-daemon`/`ssk-ipc` for a typestate driver returns zero non-test hits.
- `HypercubePathCheck` forwards to a predicate and discards `theta`: `crates/ssk-runtime/src/lib.rs:327-331` (`_theta` at `:328`).
- Production `select_egress` empties the graph: `crates/ssk-runtime/src/lib.rs:336-338` (doc: *"real multi-hop edges come from a routing policy not yet modeled"*), `:348-352` (`edges: Vec::new(), hyperedges: Vec::new()`).
- Only callers are ssk-runtime's own unit tests: `crates/ssk-runtime/src/lib.rs:833,835,845,850,862,866,891,917`.
- Trait docstring admits it: `crates/ssk-locator/src/lib.rs:122-124` (*"no implementation is wired in yet, so `select_path` below only ever receives `AlwaysPass`"*).

**Affected spec location.** SSKΩ-7 relay-fabric wording `docs/OMEGA_CORE_CONFORMANCE_SPEC.md:256`; README "policy-driven traffic routing" `README.md:39`.

**Concrete target decision.** Either wire these into a real user-reachable path (route selection consumed by a real executor, `Connection<S>` driving `run_to_outcome`) or relabel them as internal facet pre-checks in docs. Real product relevance requires the absent `ssk-netcore` executor (RB-A1).

**Minimal clean fix (honest scope, now).** Document `select_egress`/`HypercubePathCheck` as a facet-level PCH pre-check over a flat single-hop pool, and note `Connection<S>` is a compile-time model invariant not on the live path. Stop discarding `theta` if the "phase-consistent egress" claim is to be kept.

**Acceptance criterion.** No doc implies live multi-hop routing or a live connection lifecycle; or, `select_egress` is reached from a user command over a populated `LocatorGraph` and `Connection<S>` drives at least one real command.

**Required future test evidence.** If wired: a user-command-level test that reaches `select_egress` with non-empty edges and exercises a multi-edge path, plus a test driving `Connection<S>` end-to-end through a user command.

---

## RB-B4 — `MirrorOrbit::derive` orientation and `birefract` ray policy are Phase-1 placeholders

**Severity: Low–Medium.** *(Honestly disclosed in code.)*

**Description.** Two core derivations are hardcoded placeholders. `MirrorOrbit::derive` always yields `Orientation::Forward`; `birefract` populates a conservative, policy-independent locator ray regardless of intent.

**Why it is a gap.** SSKΩ-2 "real typing and locator-reality checks" overstates these — orientation logic does not exist and ray construction is not policy-driven.

**Affected files/crates (file:line).**
- `crates/ssk-core/src/lib.rs:87-88` — *"Phase 1 placeholder — no orientation logic exists yet"*; `orientation` unconditionally `Orientation::Forward`.
- `crates/ssk-core/src/lib.rs:21-24,38-45` — `birefract` hardcodes `LocalOverlay`, `RouteClass::Direct`, `TransportClass::Unknown`, budgets `100/100`; doc: real policy-driven ray *"not yet wired here"*.
- `crates/ssk-core/src/connection.rs:28-33` — `Policy` placeholder unit struct.

**Affected spec location.** `docs/OMEGA_CORE_CONFORMANCE_SPEC.md:251` (SSKΩ-2).

**Concrete target decision.** Implement orientation logic and policy-driven ray construction when `ssk-config` is threaded through (dependency of RB-B1), or narrow SSKΩ-2's wording.

**Minimal clean fix.** Narrow SSKΩ-2 text to "typed locator pool + structural trust predicate" until the real logic lands.

**Acceptance criterion.** Either the placeholders are replaced with real derivations, or the spec text no longer claims "reality checks" for them.

**Required future test evidence.** Tests that orientation varies with input and that ray budgets/classes derive from config-driven intent.

---

## RB-B5 — Three declared daemon states are never entered (`Active`, `ConfigInvalid`, `RecoveryMode`)

**Severity: Low.**

**Description.** The wire enum `DaemonState` has 8 variants; the supervisor drives only 5. `Active`, `ConfigInvalid`, `RecoveryMode` are type-model-only (level 2).

**Why it is a gap.** `ConfigInvalid` is the missing sink for RB-B1; `RecoveryMode` is unreachable despite the restart-persistence gap (RB-D3).

**Affected files/crates (file:line).** `crates/ssk-ipc/src/state.rs:12-30` (8 variants); no transition sets `DaemonState::Active`/`ConfigInvalid`/`RecoveryMode` in `crates/ssk-daemon/src/supervisor.rs`.

**Affected spec location.** State model in `docs/DESKTOP_CLIENT_ARCHITECTURE.md` (Section C).

**Concrete target decision.** Wire `ConfigInvalid` (with RB-B1) and `RecoveryMode` (with RB-D3), or remove the dead variants.

**Minimal clean fix.** Enter `ConfigInvalid` on config validation failure in `main.rs:43-49`.

**Acceptance criterion.** No `DaemonState` variant is unreachable, or unreachable ones are deleted.

**Required future test evidence.** A transition test for each newly-wired state.

---

# C. Security / Safety Blockers

## RB-C1 — "Signed capability attestation" ships as a symmetric BLAKE3 keyed-MAC, not asymmetric signing

**Severity: High.**

**Description.** README and the completion checklist mark "Signed capability attestation" as done and describe "cryptographically-audited" / "strict attestation." The shipped default is a symmetric keyed-MAC — integrity/authenticity for holders of a shared secret, **not** third-party-verifiable signatures.

**Why it is a gap.** A keyed MAC is not a signature; the doc phrasing implies stronger, asymmetric guarantees than the default build ships. `ssk-crypto` has ed25519, but it is not wired into `AttestationBinder`.

**Affected files/crates (file:line).**
- Symmetric MAC attestation, honestly documented in-crate: `crates/ssk-netadmin/src/attestation.rs:6-10,86-132` (Blake3 keyed-MAC sign/verify), `:69-74` (zero-key rejection).
- Not-yet-wired ed25519: internal audit `docs/DESKTOP_CLIENT_ARCHITECTURE.md:108-110` (*"Attestation … still **defaults** to the symmetric BLAKE3 keyed-MAC — wiring the new ed25519 impls into `AttestationBinder` … is **not yet done**"*), `:200`.

**Affected spec location.** `README.md:39,116,389`, `docs/COMPLETION_CHECKLIST.md:30` (marked [x] done), `SECURITY.md:17` ("real ed25519 signing is available via `ssk-crypto`'s `crypto` feature").

**Concrete target decision.** Either wire ed25519 into `AttestationBinder` as the shipped default, or correct all docs to say "symmetric keyed-MAC attestation (not asymmetric signatures)."

**Minimal clean fix (honest scope).** Change `README.md:39,116`, `docs/COMPLETION_CHECKLIST.md:30`, and `SECURITY.md:17` to say the shipped default is a symmetric keyed-MAC.

**Acceptance criterion.** No doc claims third-party-verifiable "signed" attestation unless `AttestationBinder` defaults to asymmetric signing.

**Required future test evidence.** If wired: a known-answer + wrong-key + tamper test proving asymmetric verification with a public key the signer does not hold.

---

## RB-C2 — IPC peer-credential **reject** path is untested in CI (the primary security control)

**Severity: Medium–High.**

**Description.** Same-user `SO_PEERCRED` peer auth is real and gates every request, but only the *accept* path is tested. The *reject* path is `#[ignore]`d with `unreachable!()` and deferred to a manual script. The Windows client-SID check is explicitly unimplemented.

**Why it is a gap.** The one genuine cross-user IPC boundary — the strongest real security control in the tree — could regress and pass all CI green.

**Affected files/crates (file:line).**
- Real accept path + gate: `crates/ssk-ipc/src/auth.rs:30-46`, called at `crates/ssk-ipc/src/server.rs:107`.
- Accept-only test: `crates/ssk-ipc/src/auth.rs:66-78`; reject test `#[ignore]`d: `crates/ssk-ipc/src/auth.rs:86-92`; manual-only verification: `scripts/manual_peer_cred_test.sh:6-8,51-60`.
- Windows unimplemented: `crates/ssk-ipc/src/auth.rs:56-60` (`CLIENT_SID_CHECK_IMPLEMENTED = false`).

**Affected spec location.** `SECURITY.md:18` (peer-cred least privilege), `SECURITY.md:47-49` (zero-key constructor claim — see RB-C3).

**Concrete target decision.** Make the reject path an automated CI test (spawn a second uid in a container, or inject a mismatched cred via a test seam).

**Minimal clean fix.** Add a hermetic test that forces `check_peer_same_user` down its reject branch and asserts `IPC_PEER_REJECTED`, wired into a CI job.

**Acceptance criterion.** A CI-run test fails if the reject path stops rejecting.

**Required future test evidence.** Automated reject-path test in `crates/ssk-ipc` running in `.github/workflows/ci.yml`.

---

## RB-C3 — `SECURITY.md` overstates zero-key constructor restriction

**Severity: Low.**

**Description.** `SECURITY.md:47-49` states zero-key constructors are compile-time restricted to test builds. Per the internal audit, `Blake3KeyedVerifier::new` / `AttestationBinder::new` are unrestricted `pub` constructors.

**Why it is a gap.** A documented compile-time restriction that does not exist. (Not exploitable today — no network peers — but a false security claim.)

**Affected files/crates (file:line).** `docs/DESKTOP_CLIENT_ARCHITECTURE.md:199` (*"**false**; … unrestricted `pub` constructors (`ssk-interop/src/lib.rs:53-57`)"*). Note the honest, correctly-scoped part: `ssk-cli` enables `insecure-test-keys` only for the `interop conformance` self-test (`crates/ssk-cli/Cargo.toml` `ssk-interop` dep), and shipped `ssk-netadmin` attestation has no such feature.

**Affected spec location.** `SECURITY.md:47-49`.

**Concrete target decision.** Either add the compile-time restriction or correct the doc.

**Minimal clean fix.** Correct `SECURITY.md:47-49` to describe the actual (runtime zero-key rejection) guarantee.

**Acceptance criterion.** `SECURITY.md` matches the constructors' real visibility/guards.

**Required future test evidence.** If restricted: a `trybuild` compile-fail test proving the zero-key constructor is unavailable outside test builds.

---

## RB-C4 — One always-pass check on the gate enforcement path; a soft Hold can mask a hard Reject in the surfaced residue

**Severity: Medium.** *(Honestly disclosed in code; does not open the gate, but under-reports.)*

**Description.** The 12-gate vector is genuinely default-deny, but (a) the Protocol axis of `HypercubeGate` always returns `Ok`, and (b) the residue-priority ladder ranks a soft Hold/Refine above a hard Reject, so a mixed candidate surfaces `Refine` and drops the Reject residue from the report.

**Why it is a gap.** For a security product the *reason* surfaced to the operator matters; a hard rejection can be silently under-reported as a soft "refine." No test covers the mixed case.

**Affected files/crates (file:line).**
- Always-pass Protocol axis: `crates/ssk-gates/src/pch.rs:139-144` (`|_sc| true`, *"Phase 3 placeholder: no fiber-invariant model yet"*).
- Priority ladder Quarantine > Refine > Reject: `crates/ssk-gates/src/lib.rs:401-409`; Hold folded into refine slot `:389-391`.
- Honestly-disclosed placeholder gates: `crates/ssk-gates/src/lib.rs:271-273,278` (`FiberGate`, risk-score proxy), `:227-229` (`CapabilityGate`, crypto deferred).
- Real default-deny aggregation (the sound part): `crates/ssk-gates/src/lib.rs:381-417`; all-gates-evaluated test `:603-629`.

**Affected spec location.** `docs/OMEGA_CORE_CONFORMANCE_SPEC.md:253` (SSKΩ-4 "twelve gates, fail-closed, PCH projection checks").

**Concrete target decision.** Ensure a hard Reject residue is never dropped when co-occurring with a Hold; retire the Protocol always-pass and the two placeholder gates with real checks.

**Minimal clean fix.** In `GateVector::evaluate`, always retain any Reject residue in `residues` even when the resolved `outcome` is `Refine`.

**Acceptance criterion.** A candidate that is simultaneously Hold (over-budget risk axis) and hard-Reject surfaces the Reject residue in the report; Protocol axis and placeholder gates perform real checks or are documented as non-enforcing.

**Required future test evidence.** A new test exercising Hold+Reject co-occurrence asserting the Reject residue is present (none exists today).

---

# D. User-Reachability Blockers

## RB-D1 — `ssk connect` is named as a network command but performs no connection (local echo only)

**Severity: Critical.** *(User-facing safety hazard — false sense of protection.)*

**Description.** The CLI subcommand `connect` takes no host/port, runs `run_to_outcome` over a hardcoded fixture with a local-echo executor, materializes into an in-memory tensor discarded at exit, and prints `outcome=/materialized=/residues=`. A user reasonably reads this as "connected/protected."

**Why it is a gap.** The command name and `pass` output actively mislead. The core pipeline behind it is real and honest (a level-4 artifact); the overclaim is the *verb*.

**Affected files/crates (file:line).**
- No destination arg: `crates/ssk-cli/src/main.rs:58-65` (clap args only `valid_fixture`/`seeded`/`epoch`).
- Local-echo executor, hardcoded fixture/pool: `crates/ssk-cli/src/main.rs:528-536` (`run_to_outcome(&sample_intent(valid_fixture), &default_pool(), …, &ssk_runtime::LocalFiberExecutor, …)`); `default_pool()` a single synthetic `LocalOverlay` locator `crates/ssk-cli/src/main.rs:1851-1868`.
- Executor "fabricates no network liveness"; digest is a content hash of the stitch's own fields: `crates/ssk-runtime/src/lib.rs:174-213` (`:195-204`, `:176-178`).
- In-memory tensor discarded: `crates/ssk-cli/src/main.rs:516-518`.
- Output is a classification string: `crates/ssk-cli/src/main.rs:546-552,576`.

**Affected spec location.** README treats `connect` as a product command implying protection (`README.md:39,261`). The command's own doc comment is honest: `crates/ssk-cli/src/main.rs:55-57` ("drives the full decision-core pipeline … to a real 3-variant RunOutcome" — a materialization, not a connection).

**Concrete target decision.** Rename the verb to match the effect; reserve `connect` for a real egress command gated behind the absent data plane (RB-A1).

**Minimal clean fix.** Rename the subcommand `connect` → `materialize` (or `simulate-intent`); change output copy from `connect: outcome=…` to explicitly label it a decision-core materialization.

**Acceptance criterion.** No user-invocable command named `connect` (or with connection-implying output) exists until it opens a real transport to a user-supplied destination.

**Required future test evidence.** When a real `connect` ships: a subprocess test that `ssk connect <host:port>` opens a real socket to a loopback endpoint and reports a truthful protection status.

---

## RB-D2 — TTL-sweep / dissolution residue finalization has zero production callers; no user can observe a sweep

**Severity: High.**

**Description.** `DissolutionManager::{is_expired,sweep,finalize_expired}` is real, unit-tested code with **no callers** in any product path. Finalized residues land in an in-memory `ResidueRegister` (no persistence, no chain, no observer). No scheduler tick, daemon epoch advance, or CLI command triggers a sweep. SSKΩ-9 marks this "✅ met."

**Why it is a gap.** "Every dissolution leaves an auditable trail" is exactly the guarantee a compliance/IR user relies on; no sweep ever runs and no residue is persisted or surfaced. The `finalize_expired` doc comment itself overclaims the residue as "hash-chained"/"auditable" while the register is neither.

**Affected files/crates (file:line).**
- Real functions, only defs + `#[cfg(test)]` + docs: `crates/ssk-tensor/src/lib.rs:211,218,237-259`; tests `:498-541`; grep for `DissolutionManager|finalize_expired|::sweep` yields no caller in `ssk-runtime`/`ssk-cli`/`ssk-daemon`/`ssk-ipc`/`ssk-netadmin`.
- In-memory register, no persistence: `crates/ssk-types/src/lib.rs:730-755`.
- In-code overclaim in the doc comment: `crates/ssk-tensor/src/lib.rs:232-234` (calls a non-persisted, non-chained in-memory residue "hash-chained"/"auditable").
- CLI `connect` `residues=<n>` is gate-pipeline residues, not a sweep: `crates/ssk-cli/src/main.rs:546-552,576`.
- No daemon sweep/residue endpoint: `crates/ssk-daemon/src/supervisor.rs:397-401`.

**Affected spec location.** `docs/OMEGA_CORE_CONFORMANCE_SPEC.md:258` (SSKΩ-9 "dissolution/TTL sweeps … ✅ met").

**Concrete target decision.** Invoke `finalize_expired` from a real driver on epoch advance; persist residues into a hash-chained ledger; expose a diagnostic surface.

**Minimal clean fix.** (a) Call `DissolutionManager::sweep`/`finalize_expired` from the daemon epoch/tick path against the backend holding accepted stitches; (b) route emitted residues into the existing `GenericFileLedgerBackend`/`AuditLedger`; (c) add an IPC/CLI query; (d) fix the doc comment at `crates/ssk-tensor/src/lib.rs:232-234`; (e) relabel SSKΩ-9's dissolution row ⚠️ until (a)–(c) land.

**Acceptance criterion.** A user can observe a swept/finalized dissolution over CLI/IPC; the residue is durably recorded in a verifiable chain.

**Required future test evidence.** An integration test that advances the epoch past a stitch's TTL, asserts a sweep ran, a residue was persisted to a verifiable chain, and the diagnostic surface returns it.

---

## RB-D3 — No cross-restart state persistence; daemon always comes up Inactive

**Severity: Medium.**

**Description.** The active profile is in-memory only; the supervisor always starts `Inactive` with `active_profile: None`. There is no load/restore, and `RecoveryMode` is never entered despite existing.

**Why it is a gap.** After a crash/restart a previously-"Protected" session silently drops to Inactive with no re-arming — a fail-open surprise for an operator (mitigated today only because protection is mock).

**Affected files/crates (file:line).** `crates/ssk-daemon/src/supervisor.rs:36` (`active_profile: Option<String>`), `:45-53` (always `StateMachine::default()` = Inactive, `active_profile: None`); no restore in `main.rs`. `RecoveryMode` variant unused: `crates/ssk-ipc/src/state.rs:29`.

**Affected spec location.** `docs/DESKTOP_CLIENT_ARCHITECTURE.md` Section F (crash recovery); SSKΩ-9 "production-hardened."

**Concrete target decision.** Persist the active profile + protection intent and restore (or enter `RecoveryMode`) on start.

**Minimal clean fix.** Write active-profile state to `state_dir()` on activate/deactivate; read it in `Supervisor::new`.

**Acceptance criterion.** Restart re-establishes (or explicitly `RecoveryMode`-flags) the prior protection state.

**Required future test evidence.** A test that activates, restarts `sskd`, and asserts the restored state.

---

# E. Test / Verification Blockers

## RB-E1 — No stitch-chain `verify()`; the persistent StitchTensor is verified only for the older `TensorEntry`, and only in memory in product paths

**Severity: Medium–High.**

**Description.** Append-only + hash-chained is real **in memory**, and the tensor-preservation theorem is genuinely tested. But `verify()` exists only for `TensorEntry` (the older ledger), not for `StitchTensorEntry`; and every product/CLI/runtime `StitchTensor` uses an in-memory backend. The file-backed stitch tensor is exercised only by a toy test.

**Why it is a gap.** SSKΩ-5's "Persistent Stitch Tensor + audit … hash-chained append" reads as a durable, verifiable, running-product store. It is transient in memory with no on-read chain verification for the stitch entry type.

**Affected files/crates (file:line).**
- Append + chain real: `crates/ssk-tensor/src/lib.rs:153,164,170-184`.
- Verify only for `TensorEntry`: `crates/ssk-tensor/src/lib.rs:44-48,373-388`; `StitchTensorEntry` `StorageBackend` has `get`/`iter`/`head` but **no** `verify`: `:63-80`.
- In-memory in every product surface: `crates/ssk-cli/src/main.rs:516-518`, `crates/ssk-runtime/src/lib.rs:769`, `crates/ssk-runtime/tests/conformance.rs:38`.
- Only file-backed stitch exercise is a toy test: `crates/ssk-tensor/src/lib.rs:585`.
- Preservation tests (the sound part): `crates/ssk-runtime/tests/conformance.rs:52-71`, `crates/ssk-runtime/src/lib.rs:807-830`.

**Affected spec location.** `docs/OMEGA_CORE_CONFORMANCE_SPEC.md:254` (SSKΩ-5).

**Concrete target decision.** Add `StorageBackend::verify()` for `StitchTensorEntry`; wire a file-backed `StitchTensor` into at least one product path.

**Minimal clean fix.** Implement and test `verify()` for the stitch chain; construct a `GenericFileLedgerBackend`-backed `StitchTensor` in a product path (daemon or CLI) instead of `GenericMemoryBackend`.

**Acceptance criterion.** A non-empty on-disk stitch chain is verifiable via a `verify()` on read, and at least one product surface persists to disk.

**Required future test evidence.** A test that persists a stitch chain across a reopen and verifies it via the new `verify()`.

---

## RB-E2 — No integration/system test exercises any real network/system effect; every collaborator is a mock or local double

**Severity: High.**

**Description.** The green CI suite validates a level-4 core artifact. No test in the tree drives any TCP/UDP/TLS/DNS effect; every test collaborator is `LocalFiberExecutor` (deterministic echo) or `MockDataPlane` (AlwaysUp/AlwaysDown). The one real cross-process test (`round_trip.rs`) exercises only the local Unix-socket control plane and reaches `Protected` via the mock.

**Why it is a gap.** CI cannot and does not demonstrate routing, protection, or a Proxifier effect. "Green = done" is therefore invalid at the product level. Section-W "conformance" tests measure model-internal invariants, not system invariants (their header wording "end-to-end" means end-to-end of the math model).

**Affected files/crates (file:line).**
- Conformance bound to local doubles: `crates/ssk-runtime/tests/conformance.rs:22` (`LocalOverlay` only), `:60,85,116,127` (`LocalFiberExecutor`).
- CI runs mocks only: `.github/workflows/ci.yml:20-27,29-35,37-43,45-51,83-89` (build/test/proptest/replay/interop/netadmin — all in-process).
- `breaking_change_guard` fails nothing: `.github/workflows/ci.yml:69-73` (`echo` only).
- Real cross-process test reaches Protected via mock: `crates/ssk-daemon/tests/round_trip.rs:84` + `AlwaysUpMockDataPlane` at `crates/ssk-daemon/src/main.rs:53`.

**Affected spec location.** README "fail-closed enforcement at every layer" `README.md:32`; SSKΩ-8 "full simulation + conformance testbed" `docs/OMEGA_CORE_CONFORMANCE_SPEC.md:257`; conformance header `crates/ssk-runtime/tests/conformance.rs:1-4`.

**Concrete target decision.** Gate any "done" claim on a new class of test that drives real traffic through a real `RouteExecutor` and asserts a real network effect + audit append + kill-switch teardown. Relabel the Section-W header to "abstract decision core (local-overlay/local-echo; no network effect)."

**Minimal clean fix (docs now).** Amend `crates/ssk-runtime/tests/conformance.rs:1-4` to strike "system"/network implications; scope CI claims to "level-4 core artifact."

**Acceptance criterion.** A hermetic end-to-end network test exists and is green (co-gated with RB-A1), or all claims are scoped to the model level.

**Required future test evidence.** The end-to-end network test described in RB-A1's evidence row.

---

## RB-E3 — CLI `chaos drill` runs against a stub, not the real system under test

**Severity: Low.**

**Description.** The `chaos drill` command injects faults into a stub gate closure, not the real pipeline; the CLI comment says so.

**Why it is a gap.** "Defensive adversary sim" reads as testing the real system; the CLI variant tests a mimic.

**Affected files/crates (file:line).** `crates/ssk-cli/src/main.rs:1378-1398` (*"Stub runner: mimics the gate heuristic"*). (The `ssk-faultscan` CI job `.github/workflows/ci.yml:99-105` does run against the model, which is the honest part.)

**Affected spec location.** `docs/OMEGA_CORE_CONFORMANCE_SPEC.md:257` (SSKΩ-8), `SECURITY.md:74-84` (fault playbook).

**Concrete target decision.** Point the CLI chaos runner at the real gate vector (or label it a demonstration).

**Minimal clean fix.** Replace the stub closure with a call to the real `GateVector` path, or rename the command output to "demo".

**Acceptance criterion.** `chaos drill` exercises the real gate pipeline, or is documented as a demonstration.

**Required future test evidence.** A test that a chaos fault triggers the expected reject through the real gate vector.

---

# F. Documentation / Spec Blockers

## RB-F1 — Marketing docs overclaim a delivered product; the daemon's live status is the honest layer they contradict

**Severity: High.** *(The over-claim set; RB-A1 is its most severe single instance.)*

**Description.** README / NETADMIN_SPEC / COMPLETION_CHECKLIST assert delivered traffic routing, Raw-TCP/TLS/DNS adapters, "cryptographically-audited," and "production-oriented." The daemon's runtime status is honest (`dns_protected=false`, empty flows, "ssk-netcore not yet integrated"); the overclaim lives in prose. The repo even contains its own corrective audit (`docs/DESKTOP_CLIENT_ARCHITECTURE.md`, Section B.6 literally titled "Doc-vs-code discrepancies to correct").

**Why it is a gap.** The documents a reader trusts most (README, checklist) are the least accurate; the runtime is the most accurate. Shipping on the prose would present a math-model core as a network product.

**Affected quotes vs code (file:line).**
- `README.md:3` "Production-oriented … runtime" vs `docs/DESKTOP_CLIENT_ARCHITECTURE.md:33-38,114-118` ("It is **not** a network runtime").
- `README.md:39`, `docs/NETADMIN_SPEC.md:5-8`, `docs/COMPLETION_CHECKLIST.md:33` "Proxifier replacement / done" vs `crates/ssk-netadmin/src/adapter.rs:37-40` (no `connect()`), `docs/DESKTOP_CLIENT_ARCHITECTURE.md:54-56`.
- `README.md:283-292` "DirectAdapter = Raw TCP / TlsTunnelAdapter / DnsOverrideAdapter" vs `crates/ssk-netadmin/src/adapter.rs:63-71,218-262` (descriptor structs; `DnsOverrideAdapter` stores host/port, never resolves).
- `README.md:39,116` / `docs/COMPLETION_CHECKLIST.md:30` "signed capability attestation done" vs RB-C1.
- `README.md:397` Desktop GUI vs `docs/DESKTOP_CLIENT_ARCHITECTURE.md:201` ("no Tauri, HTTP endpoints, daemon, or updater exist"); no GUI/Tauri crate in the tree.

**Affected spec location.** As quoted above; SSKΩ summary `docs/OMEGA_CORE_CONFORMANCE_SPEC.md:39` (see RB-A3).

**Concrete target decision.** Align README / NETADMIN_SPEC / COMPLETION_CHECKLIST with the already-honest `DESKTOP_CLIENT_ARCHITECTURE.md` audit and the daemon's live status. Mark absent capabilities as Phase-3/4 not-yet-shipped.

**Minimal clean fix.** Rewrite the offending README/checklist lines to describe planning/decision/audit capability; change "done" markers on data-plane, signing, and GUI rows to "planned / not implemented."

**Acceptance criterion.** No user-facing doc asserts a capability the daemon's live status contradicts; the "declared non-goals" (`docs/DESKTOP_CLIENT_ARCHITECTURE.md:237-241`) remain intact.

**Required future test evidence.** N/A (doc reconciliation), verifiable by contrasting each doc claim against the cited code line.

---

## RB-F2 — Spec/positioning diagrams show a live data-plane layer that is descriptor-only

**Severity: Medium.** *(Subset of RB-F1; called out because diagrams read as architecture-of-record.)*

**Description.** `lib.rs`/spec diagrams draw "Data Plane Adapters (SOCKS5/HTTP/TLS/Direct/DNS)" as a live layer enforcing fail-closed on real flows; there is no flow to block.

**Affected files/crates (file:line).** `crates/ssk-netadmin/src/lib.rs:11-36` (box diagram, `:22-25` live-layer claim, `:33-36` "every layer … denies the flow"); `docs/NETADMIN_SPEC.md:15-25`. Honest counter-marker: `crates/ssk-netadmin/src/adapter.rs:5-9`.

**Concrete target decision.** Annotate the diagram boxes as "descriptor-only (transport = caller / ssk-netcore Phase 3)."

**Minimal clean fix.** Edit `crates/ssk-netadmin/src/lib.rs:22-25,33-36` and `docs/NETADMIN_SPEC.md:15-25` to mark the adapter layer as planning/descriptor-only.

**Acceptance criterion.** No diagram depicts a live data plane the code lacks.

**Required future test evidence.** N/A.

---

# G. Packaging / Distribution Blockers

## RB-G1 — Release workflow ships a source tarball, not the built binaries it claims to package

**Severity: Medium–High.**

**Description.** README says the release workflow "packages platform binaries and a crate source archive." The workflow builds `--release` and then tars only source (`crates`, `Cargo.toml`, `README.md`, `docs`); the compiled `ssk`/`sskd` are never included.

**Why it is a gap.** The released artifact is not installable/runnable — the build output is discarded. Single builder (`ubuntu-latest`) means no macOS/Windows/aarch64 artifacts even if binaries were shipped.

**Affected files/crates (file:line).** `.github/workflows/release.yml:19` (`cargo build --workspace --release`), `:20` (`tar -czf … crates Cargo.toml README.md docs` — source only), `:13` (single `ubuntu-latest` builder). Binaries that exist: `crates/ssk-cli/Cargo.toml:7-9` (`ssk`), `crates/ssk-daemon/Cargo.toml:7-9` (`sskd`).

**Affected spec location.** `README.md:381`.

**Concrete target decision.** Package the built binaries (and, for a real product, a cross-platform matrix), or correct the README.

**Minimal clean fix.** Add `target/release/ssk` and `target/release/sskd` to the tarred artifact in `.github/workflows/release.yml:20`, or change `README.md:381` to "source archive only."

**Acceptance criterion.** A tagged release produces a runnable binary artifact, or the doc no longer claims to.

**Required future test evidence.** A release-dry-run job that asserts the artifact contains executable `ssk`/`sskd`.

---

## RB-G2 — No OS-service integration; only SIGINT handled; SIGTERM/SIGKILL leaves a stale lock that blocks restart

**Severity: Medium.**

**Description.** There are no systemd/launchd units, no installer/Dockerfile/`.deb`/PKGBUILD, no PID file, no daemonization. The daemon traps only `ctrl_c()` (SIGINT); a service manager's SIGTERM is not trapped, and the lock file is removed only on the normal exit path — so a service stop leaves a stale `sskd.lock` that blocks the next `create_new`.

**Why it is a gap.** "Autostart background daemon / service install" is promised; none of the OS-service surface exists, and the lock behavior is a concrete operational defect for any service manager.

**Affected files/crates (file:line).** `crates/ssk-daemon/src/main.rs:71-75` (only `tokio::signal::ctrl_c()`), `:22-36,60` (single-instance lock via `create_new`, removed only on normal/ctrl-c exit). No `.service`/`.plist`/`.socket`/installer found in the tree. Windows named-pipe path is `#[cfg(windows)]` and never compiled/tested: `crates/ssk-daemon/src/main.rs:78-93`, `crates/ssk-ipc/src/server.rs:123-127`.

**Affected spec location.** `README.md:381`; `docs/DESKTOP_CLIENT_ARCHITECTURE.md` Sections E.2/F (autostart service install), `docs/OMEGA_CORE_CONFORMANCE_SPEC.md:258` (SSKΩ-9 "deployment audit").

**Concrete target decision.** Add service units + SIGTERM/SIGHUP handling with lock cleanup, or document that install is manual (`cargo build --release` / foreground run) with no service integration.

**Minimal clean fix.** Trap SIGTERM alongside SIGINT and remove the lock on all shutdown paths (`crates/ssk-daemon/src/main.rs:71`); add a systemd `.service` and a launchd `.plist`.

**Acceptance criterion.** A service manager can start/stop the daemon cleanly with no stale lock; or docs state install is manual with no service integration.

**Required future test evidence.** A test that a SIGTERM shutdown removes the lock and permits immediate restart.

---

# H. Nice-to-have (explicitly NOT a blocker)

These are honest hardening/quality items. None blocks an appropriately-scoped release.

## NH-H1 — `no_std_core` CI job omits the `Swatinem/rust-cache` step
Cosmetic inconsistency vs other jobs (`.github/workflows/ci.yml:75-81`); no correctness impact. *Fix: add the cache step for parity.*

## NH-H2 — `GenericFileLedgerBackend` append is O(n) JSON rewrite
Read-all → push → write-all on each append, JSON not CBOR (`crates/ssk-tensor/src/lib.rs:339-343`). Functional; a scaling nicety, not a correctness gap. *Fix: incremental append + CBOR when the ledger becomes hot.*

## NH-H3 — `ssk-stitch::from_intent` hardcodes candidate flags to `true`
`seam_ok/boundary_complete/replay_ready/focus_ready = true` by fiat (`crates/ssk-stitch/src/lib.rs:17-20`). The gate layer re-checks these, so it is not a soundness hole, but the flags are asserted, not derived. *Fix: derive from real candidate state so SSKΩ-3's "carries" is substantive.*

## NH-H4 — JSON-Schema mirror is a hand-written literal that can drift from the types
`schema_json()` is a string literal checked only by a `contains(...)` smoke test (`crates/ssk-config/src/lib.rs:846-995,1035-1043`). Low risk today. *Fix: generate the schema from the types, or add a round-trip validation test.*

## NH-H5 — PCH scaffolding types exist only for spec-surface parity
`ConnectionCell`/`CellAddr`/`CellWeight`/`Constraint`/`GateStatus`/`AxisWeight` are not consumed by `Hypercube::check` (`crates/ssk-gates/src/pch.rs:32-92`). Harmless dead type-model. *Fix: delete or wire when the full hypercube lands.*

---

## Blocker summary matrix

| ID | Category | Severity | One-line |
|---|---|---|---|
| **RB-A1** | Release / Architecture / Docs | **Critical** | No data plane; product claims traffic protection that does not exist |
| **RB-A2** | Release | High | `ssk-core --no-default-features` fails; advertised `no_std` guarantee broken |
| **RB-A3** | Release / Docs | High | SSKΩ "all met" summary contradicts its own ⚠️ SSKΩ-7 row |
| **RB-B1** | Architecture | High | Validated config parsed then discarded; drives nothing |
| **RB-B2** | Architecture | High | Daemon never writes audit ledger; verify is vacuous |
| **RB-B3** | Architecture | Medium | Typestate & path-selector are dead outside tests |
| **RB-B4** | Architecture | Low–Med | `MirrorOrbit::derive`/`birefract` Phase-1 placeholders |
| **RB-B5** | Architecture | Low | 3 daemon states never entered |
| **RB-C1** | Security | High | "Signed attestation" is a symmetric keyed-MAC |
| **RB-C2** | Security | Med–High | IPC peer-cred reject path untested in CI |
| **RB-C3** | Security | Low | `SECURITY.md` overstates zero-key constructor restriction |
| **RB-C4** | Security | Medium | Always-pass Protocol axis; Hold can mask Reject residue |
| **RB-D1** | User-Reachability | **Critical** | `ssk connect` implies a connection; performs a local echo |
| **RB-D2** | User-Reachability | High | TTL sweep has no callers; no user can observe it |
| **RB-D3** | User-Reachability | Medium | No cross-restart state persistence |
| **RB-E1** | Test/Verification | Med–High | No stitch-chain verify; persistence in-memory only in product |
| **RB-E2** | Test/Verification | High | No test exercises any real network effect |
| **RB-E3** | Test/Verification | Low | CLI `chaos drill` runs a stub |
| **RB-F1** | Documentation | High | Marketing docs overclaim a delivered product |
| **RB-F2** | Documentation | Medium | Diagrams depict a live data-plane layer that is descriptor-only |
| **RB-G1** | Packaging | Med–High | Release ships source, not the built binaries it claims |
| **RB-G2** | Packaging | Medium | No service units; SIGTERM leaves a stale lock |
| NH-H1..H5 | Nice-to-have | — | Non-blocking hardening items |

---

## Honest bottom line

What exists is real and worth respecting: a deterministic, tested, fail-closed **decision / audit / planning core** (real BCIK crossing, real gate vector, genuine re-execution replay, compile-time typestate, a real local Unix-socket control plane with a supervised-failure watchdog) — a solid **level-4 code artifact**. The code and the daemon's *live status* are largely honest about their limits (`dns_protected=false`, empty flows, "ssk-netcore not yet integrated", Phase-N placeholders), and the repo carries its own corrective audit at `docs/DESKTOP_CLIENT_ARCHITECTURE.md`.

What is not true is the **product contract in the marketing docs**: there is no data plane (RB-A1), so no traffic is protected, routed, or DNS-shielded; the one rung that would require it (SSKΩ-7) is self-graded ⚠️ and deferred to the absent `ssk-netcore` crate; and the advertised `no_std` guarantee does not compile (RB-A2). Until RB-A1 and RB-A2 are resolved — and until an end-to-end test drives a real network effect (RB-E2) — the only defensible release is one **scoped to the decision/audit/planning core**, with every traffic-protection claim removed or explicitly marked not-yet-implemented.