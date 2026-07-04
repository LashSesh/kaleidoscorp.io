# SSKΩ Conformance Re-Evaluation

**Repository:** `kaleidoscorp.io` · **Branch:** `claude/rust-arch-audit-gaps-immuk1` · **Date:** 2026-07-04
**Scope:** Independent re-grading of the self-declared SSKΩ-0 … SSKΩ-9 ladder in `docs/OMEGA_CORE_CONFORMANCE_SPEC.md:249-258` against the code in the tree.

## Purpose and reading guide

The SSKΩ ladder in `docs/OMEGA_CORE_CONFORMANCE_SPEC.md:249-258` is a **decision-core-model** ladder. Nine of its ten rungs describe properties of a deterministic, in-process math/audit engine; exactly one rung (SSKΩ-7) requires a real network/system effect. This re-evaluation grades each rung twice where the two diverge: as a **code artifact** (does the code exist, compile, run locally, and pass tests?) and as a **product/network capability** (does a user-reachable path produce the promised traffic-protection/routing/persistence effect?).

Two maturity anchors are used throughout, consistent with the audit inputs:
- **Level 4** — locally executable, deterministic, tested code artifact with real internal collaborators; no external/network/system effect.
- **Level 5+** — real system/network effect, reachable by a user-facing command.

The self-grades in the spec are honest for the *core-model* reading of most rungs. They diverge sharply from reality on the rungs that the product contract (`README.md:39` "traffic routing without third-party proxy software"; `docs/NETADMIN_SPEC.md:5-8` "replaces … Proxifier") actually depends on: **SSKΩ-2, SSKΩ-5, SSKΩ-7, and SSKΩ-9**. Where the code is honestly incomplete, this document cites the in-code honesty marker. Where the docs overclaim, it quotes and contrasts.

---

## Summary table

| Rung | Definition (spec) | Self-grade | Re-eval status | Artifact level | Network/product level |
|------|-------------------|-----------|----------------|----------------|-----------------------|
| **SSKΩ-0** | Typed model: `ssk-types`/`ssk-core` compile; Core/Identity/Locator separately typed | ✅ met | **PASS** (default features); no_std guarantee broken | 4 | — |
| **SSKΩ-1** | Deterministic core + scheduler; replayable phase selection | ✅ met | **PASS** | 4 | — |
| **SSKΩ-2** | Mirror-facet orbit + locator pool with locator-reality checks | ✅ met | **PARTIAL** | 4 | ~1 |
| **SSKΩ-3** | BCIK `StitchCandidate` pipeline: seam/boundary/gate/trace/replay | ✅ met | **PASS** | 4 | — |
| **SSKΩ-4** | Gate vector + boundary residues: 12 gates, fail-closed, PCH | ✅ met | **PASS** (disclosed caveats) | 4 | — |
| **SSKΩ-5** | Persistent Stitch Tensor + audit: hash-chained append, verify | ✅ met | **PARTIAL** | 4 (in-mem) | 3 |
| **SSKΩ-6** | Concave Reanalysis Focus + replay determinism | ✅ met | **PASS** | 4 | — |
| **SSKΩ-7** | Locator pool + relay-fabric adapters: **real egress adapters, health probing** | ⚠️ (self-flagged) | **FAIL** | 2 (type model) | 2 |
| **SSKΩ-8** | Full simulation + conformance testbed | ✅ met | **PASS** (in-process testbed) | 4 | — |
| **SSKΩ-9** | Production-hardened runtime profile: TTL sweeps, ledger verify, deployment audit | ✅ met | **PARTIAL** | 3–4 (isolated) | 2 |

**Headline finding.** The spec's own summary at `docs/OMEGA_CORE_CONFORMANCE_SPEC.md:39` ("SSKΩ-0 through SSKΩ-9 are all met") is internally contradicted by its own `:256` ⚠️ row for SSKΩ-7. SSKΩ-7 is the single rung whose definition requires a real network effect, and it is the one that the product contract (Proxifier replacement, DNS protection, kill-switch over real traffic) rests on entirely. It is **not met**, and it is deferred to a crate — `ssk-netcore` — that **does not exist in the workspace** (`ls crates/ssk-netcore` → No such file or directory). Two additional rungs (SSKΩ-5, SSKΩ-9) are graded PARTIAL rather than met because their "persistent" / "production-hardened" language describes durability and integration that no product surface currently reaches.

---

## SSKΩ-0 — Typed model

**Original claim.** *"Typed model: `ssk-types`/`ssk-core` compile; Core, Identity Plane, Locator Plane exist and are separately typed."* Self-graded **✅ met** (`docs/OMEGA_CORE_CONFORMANCE_SPEC.md:249`).

**Current real status.** The typed model exists and compiles under **default (std) features** — `cargo build --workspace` is green. Core, Identity, and Locator are separately typed crates. The rung is fully honest only for the default build: `ssk-core` does **not** compile under `--no-default-features`, which `README.md:102` advertises as a CI-verified guarantee. As a core artifact this is real (level 4); it is not by itself a product capability.

**Evidence.**
- Separately-typed planes: `crates/ssk-core/src/lib.rs:21-45` (`Core` / `birefract`), `ssk-identity` `derive_identity_facet`, `crates/ssk-locator/src/lib.rs` `StaticLocatorPool`.
- no_std break reproduced: `cargo check -p ssk-core --no-default-features` → exit 101, three errors E0425/E0433 "cannot find type `Vec`" at `crates/ssk-core/src/connection.rs:55` (`-> Result<Vec<StitchId>, FaultKind>`), `:78` (`stitches: Vec<StitchId>`), `:87` (`Vec::new()`) — bare `Vec` with no `use alloc::vec::Vec` (the file imports only `use core::marker::PhantomData` at `:18`).
- Advertised guarantee: `README.md:102`, `:342-343`, `:371` state `ssk-core` is `no_std`-friendly and "verified in CI via `cargo check --no-default-features`"; the `no_std_core` CI job is defined at `.github/workflows/ci.yml:75-81`.

**Missing evidence.** A green `cargo check -p ssk-core --no-default-features`; evidence that the `no_std_core` CI job has actually passed on this branch (as written, the command exits 101).

**Risk of a false checkmark.** Low for the rung's literal "compile" claim — the default build is green. Real risk on the *advertised no_std guarantee*: README and CI claim a verified capability that is broken in this exact tree, a concrete counterexample for any reader equating "all green" with "delivered."

**Status: PASS** (rung-as-defined, default features).

**What is needed to truly PASS the advertised guarantee.** Add `use alloc::vec::Vec;` (and `extern crate alloc;` if absent) to `crates/ssk-core/src/connection.rs`, then confirm `cargo check -p ssk-core --no-default-features` exits 0 and the `no_std_core` job goes green on this branch — or delete the no_std claim from `README.md`/CI.

---

## SSKΩ-1 — Deterministic core + scheduler

**Original claim.** *"Deterministic core + scheduler: fixed-point phase, deterministic tick, replayable phase selection."* Self-graded **✅ met** (`spec:250`).

**Current real status.** Genuinely met as a core-model artifact. `HypertoroidalScheduler` advances phase deterministically on `T^n`; `Deterministic` mode applies zero jitter, `Seeded` mode derives jitter from `(seed, tick)` via `Pcg64` so replay reproduces phase points bit-for-bit; there is no `SystemTime`/`thread_rng` on the path. Real collaborators, test-backed. Level 4; no network effect is claimed or needed here.

**Evidence.**
- `crates/ssk-scheduler/src/lib.rs:40-66` (tick), `:72-87` (seeded PCG jitter), `:73-74` (deterministic no-jitter).
- Mode selected purely from `DeterminismContext`: `crates/ssk-runtime/src/lib.rs:114-124`.
- Tests: `deterministic_tick` proptest (`scheduler/src/lib.rs:135-146`); `deterministic_mode_applies_no_jitter` (`:148-159`); `deterministic_context_is_reproducible` (`ssk-runtime/src/lib.rs:738-766`); `run_to_outcome_is_deterministic` (`:922-953`, equal `RunOutcome` and equal `tensor.head()` across two independent runs).

**Missing evidence.** None for the model claim. No network/session determinism is asserted.

**Risk of a false checkmark.** Low. Determinism is real and test-backed over real collaborators. Residual risk only if "deterministic" is read as "reproducible network session" — the executor is a local echo, so replay reproduces model state, not traffic.

**Status: PASS.**

**What is needed to truly PASS.** Already passes as defined; no action required.

---

## SSKΩ-2 — Mirror-facet orbit + locator pool with locator-reality checks

**Original claim.** *"Mirror-facet orbit + locator pool with real typing and locator-reality checks."* Self-graded **✅ met**, citing content-addressed `MirrorOrbit` and `claims_external_plurality()` (`spec:251`).

**Current real status.** Real as typing/model, shallow as a "reality check." `MirrorOrbit` derive/recover is real Phase-1 algebra, but `MirrorOrbit::derive` orientation is a hardcoded placeholder (`Orientation::Forward` always). The "locator-reality check" (`locator_axes_consistent` / PCH) is a **trivial three-field boolean predicate** — `loc.trusted && loc.trust != Untrusted && loc.risk_score <= 70` — with no liveness, no probing, and it does not even check `health == Live`. The locator pool is a flat static in-memory pool; multi-hop edges are not modeled in production. Level 4 core artifact; ~level 1 as a routing product capability.

**Evidence.**
- Orientation placeholder: `crates/ssk-core/src/lib.rs:87-88` — *"Phase 1 placeholder — no orientation logic exists yet."*
- Reality predicate: `crates/ssk-gates/src/pch.rs:195-197` (`LOCATOR_RISK_CEILING = 70` at `pch.rs:13`); reads only `trusted`/`trust`/`risk_score`, does not check `health == Live`.
- Production `select_egress` empties the routing graph: `crates/ssk-runtime/src/lib.rs:336-338` (docstring: *"real multi-hop edges come from a routing policy not yet modeled"*), `:348-352` (`edges: Vec::new(), hyperedges: Vec::new()`).
- Facet-recovery invariant test: `crates/ssk-runtime/tests/conformance.rs:42-48`.

**Missing evidence.** A locator-reality check that observes real reachability/liveness (probe/health) rather than reading three struct fields; a populated multi-hop relay graph on a production path rather than only in test fixtures.

**Risk of a false checkmark.** Medium. "✅ met" overstates "locator-reality checks": the shipped check is a field comparison on an in-memory struct with no external observation, so it cannot detect a locator that is unreachable or dead. A reader assumes locators are validated against reality; they are not.

**Status: PARTIAL.**

**What is needed to truly PASS.** Either (a) narrow the rung text to "typed locator pool + structural trust predicate" (honest scope), or (b) implement an actual liveness/health probe (requiring the absent `ssk-netcore` transport) and add `health == Live` to the predicate. Separately, implement `MirrorOrbit` orientation logic to retire the Phase-1 placeholder at `ssk-core/src/lib.rs:87-88`.

---

## SSKΩ-3 — BCIK StitchCandidate pipeline

**Original claim.** *"BCIK `StitchCandidate` pipeline: every crossing carries seam, boundary, gate, trace, replay."* Self-graded **✅ met** (`spec:252`).

**Current real status.** Met as a core-model artifact. `run_to_outcome` performs a **real cryptographic BCIK crossing** (`Bcik::cross` over a Blake3 hash provider) returning `Closed`/`Residue`, chains a real Blake3 hash-chained trace over five `PipelineStep`s, and carries seam/boundary/gate/trace/replay on the candidate. The one caveat: the candidate builder is trivial and **hardcodes** `seam_ok/boundary_complete/replay_ready/focus_ready = true`, so those flags are asserted at construction rather than derived. Level 4; no network crossing.

**Evidence.**
- BCIK crossing: `crates/ssk-runtime/src/lib.rs:268-283` (`Bcik::new(...).cross(...)`; open seam → residue dissolve, not silent).
- Trace chaining: `:136-159` via `ssk-audit::chain_trace` (Blake3, genesis → entry).
- Candidate build hardcodes flags: `crates/ssk-stitch/src/lib.rs:5-23`, specifically `:17-20`.
- `BcikGate` drives the real `cross()`: `crates/ssk-gates/src/lib.rs:171-174`.

**Missing evidence.** Validation (not assertion) of `seam_ok`/`boundary_complete`/`replay_ready` upstream in `from_intent`; they are currently hardcoded `true`. No network/session semantics are claimed.

**Risk of a false checkmark.** Low-to-medium. The crossing/trace/replay carriage is real; the caveat is that boundary/seam/replay-readiness are set true by fiat at construction, so "carries" is structurally true while their *truth* is not independently established.

**Status: PASS.**

**What is needed to truly harden.** Make `ssk-stitch::from_intent` derive `seam_ok`/`boundary_complete`/`replay_ready` from real candidate state instead of hardcoding `true`.

---

## SSKΩ-4 — Gate vector + boundary residues

**Original claim.** *"Gate vector + boundary residues: twelve gates, fail-closed, typed residues, PCH projection checks."* Self-graded **✅ met** (`spec:253`).

**Current real status.** Met as a core-model artifact with three disclosed caveats. Twelve real gate structs are evaluated with **no early break**; the outcome is `Pass` only when no gate objected (genuine default-deny); typed residues are emitted on every fail path; `HypercubeGate` drives a real 9-axis PCH. Caveats: (1) exactly one always-pass check sits on the enforcement path — `ProtocolProjector` returns `true` (Phase-3 placeholder); (2) `FiberGate` and `CapabilityGate` are honestly-disclosed placeholders (risk-score proxy / no cryptographic re-verification); (3) in the priority ladder a soft `Hold`/`Refine` **outranks** a hard `Reject`, which can mask a rejection's residue in the surfaced report (it never opens the gate, but it can under-report). Level 4; the gates gate an abstract `StitchCandidate`, not real traffic.

**Evidence.**
- Fail-closed aggregation: `crates/ssk-gates/src/lib.rs:381-417` (`Pass` only in the final `else` at `:407-408`, no early break); twelve gates registered `:357-374`.
- All-gates-evaluated proof: `all_twelve_gates_are_evaluated_even_after_an_early_reject` (`lib.rs:603-629`).
- Always-pass Protocol axis: `crates/ssk-gates/src/pch.rs:139-144` (*"Phase 3 placeholder: no fiber-invariant model yet"*).
- Disclosed placeholders: `FiberGate` `lib.rs:271-273`, `:278`; `CapabilityGate` crypto deferred `lib.rs:227-229`.
- Hold-outranks-Reject priority: `lib.rs:401-406` (Quarantine > Refine > Reject).
- Real 9-axis check: `pch.rs:223-262`.

**Missing evidence.** A test exercising the mixed `Hold`+`Reject` case (none exists today) to prove the surfaced residue does not silently downgrade a hard rejection; a real fiber-transform model and real capability crypto re-verification to retire the two placeholder gates and the Protocol always-pass axis.

**Risk of a false checkmark.** Medium. "✅ met" is defensible for default-deny, but the Hold-masks-Reject priority and the always-pass Protocol axis mean enforcement is not as complete as "twelve gates + PCH" implies. For a security product, the reason surfaced to the operator can under-report a hard reject.

**Status: PASS** (fail-closed model, with caveats recorded).

**What is needed to fully harden.** Retire `ProtocolProjector`'s `|_sc| true` and the `FiberGate`/`CapabilityGate` placeholders with real checks; add a test for `Hold`+`Reject` co-occurrence and ensure a hard `Reject` residue is never dropped from the report.

---

## SSKΩ-5 — Persistent Stitch Tensor + audit

**Original claim.** *"Persistent Stitch Tensor + audit: hash-chained append, storage backends, tensor-preservation theorem tested."* Self-graded **✅ met** (Phase 4), wired into `run_to_outcome` and `Connection::materialize`; preservation theorem "proven end-to-end" (`spec:254`).

**Current real status.** Partially met. Append-only + hash-chained is real **in memory**, and the tensor-preservation theorem is genuinely tested with real collaborators. But "Persistent" is overstated on two counts: (1) every production/CLI/runtime `StitchTensor` uses an **in-memory** backend — the file-backed stitch tensor is exercised only by one toy test; (2) there is **no chain-verify for `StitchTensorEntry`** — `verify()` exists only for the older `TensorEntry` ledger. Separately, the daemon's persisted audit ledger is real infrastructure but the daemon **never writes to it**, so `VerifyAuditChain` verifies an **empty** chain (vacuously green). Level 4 as an in-memory artifact; not level 5 as a durable/verifiable persistent product store.

**Evidence.**
- Append + chain: `crates/ssk-tensor/src/lib.rs:153`, `:164`, `:170-184`.
- Verify exists only for `TensorEntry`: `lib.rs:44-48`, `:373-388`; the `StitchTensorEntry` `StorageBackend` (`lib.rs:63-80`) has `get`/`iter`/`head` but **no** `verify()`.
- Production backends are in-memory: CLI `connect` uses `GenericMemoryBackend` (`crates/ssk-cli/src/main.rs:516-518`); runtime/conformance `GenericMemoryBackend` (`crates/ssk-runtime/src/lib.rs:769`, `crates/ssk-runtime/tests/conformance.rs:38`). The only file-backed stitch exercise is the toy test `generic_file_backend_persists_a_non_tensor_entry_type` (`ssk-tensor/src/lib.rs:585`).
- Preservation theorem tests: `failed_gate_preserves_the_tensor` (`conformance.rs:52-71`); `run_to_outcome_dissolves_and_preserves_the_tensor_on_a_failed_gate` (`ssk-runtime/src/lib.rs:807-830`).
- Daemon never records: no `.audit.record(...)` call anywhere in `crates/ssk-daemon/src/supervisor.rs` (only `.entries()`/`.verify()` at `:240`, `:404`, `:419`, `:422`); `audit_head` always `None` (`supervisor.rs:239-243`); the round-trip `assert!(v.ok)` at `crates/ssk-daemon/tests/round_trip.rs:106` therefore passes on a zero-entry ledger.

**Missing evidence.** A `verify()` for the `StitchTensorEntry` chain; a production path that constructs a file-backed `StitchTensor`; a daemon request path that actually calls `record()` so `VerifyAuditChain` is non-vacuous; a test verifying a non-empty on-disk stitch chain.

**Risk of a false checkmark.** High. "Persistent Stitch Tensor + audit … hash-chained append" reads as a durable, verifiable, running-product store; in reality the stitch tensor is transient in-memory on every product surface, the stitch chain has no verify function, and the daemon's audit ledger is never written and "verifies" green only because it is empty. This is the sharpest gap between "✅ met" and reality after SSKΩ-7, and it directly undercuts the `README.md:39` "cryptographically-audited" claim: no daemon runtime path demonstrates a non-empty audited chain.

**Status: PARTIAL.**

**What is needed to truly PASS.** Add `StorageBackend::verify()` for `StitchTensorEntry` and test it on a non-empty chain; wire a file-backed `StitchTensor` into at least one product path; make the daemon call `AuditLedger::record()` on activate/deactivate/route decisions so `VerifyAuditChain` checks a real chain; then assert a non-empty verified chain in `round_trip.rs`.

---

## SSKΩ-6 — Concave Reanalysis Focus + replay

**Original claim.** *"Concave Reanalysis Focus + replay: class reconstruction, replay determinism harness green."* Self-graded **✅ met** (Phase 5); `run_to_outcome` drives BCIK → tensor → FiberExecutor → FocusEngine (`spec:255`).

**Current real status.** Met as a core-model artifact. `FocusEngine::reanalyze` is real logic; the replay engine **genuinely re-executes** the pipeline (`execute_pipeline`) from the original inputs and diffs freshly-recomputed digests against a commitment manifest — it is not stored-artifact-vs-stored-artifact comparison. One caveat: focus analyzes the **fabricated local `Response`** from `LocalFiberExecutor` (a content-hash echo whose docstring states it *"fabricates no network liveness"*), and replay re-runs the same pure core, so "replay fidelity" here means model reproducibility, not session reproduction. Level 4.

**Evidence.**
- Genuine re-execution: `crates/ssk-replay/src/lib.rs:55` (`execute_pipeline`), recompute + compare `:57-70`; manifest is a commitment, not an archive, per docstring `:19-24`.
- Focus over fabricated `Response`: `run_to_outcome` `crates/ssk-runtime/src/lib.rs:301-306`; `LocalFiberExecutor` echo `:189-213` (*"fabricates no network liveness"* `:176-178`).
- Tests: `genuinely_re_executed_run_matches_its_own_manifest` (`ssk-replay/src/lib.rs:110-137`); `replay_vectors.rs:30-55`; CI `replay_vectors` job `.github/workflows/ci.yml:37-43`.

**Missing evidence.** None for the model claim. No network-session replay is claimed; the executor is deliberately a local echo.

**Risk of a false checkmark.** Low-to-medium. Real and tested as a model property. Risk only if "replay-verifiable" is read as reproducing a real protected session — it reproduces the deterministic math core.

**Status: PASS.**

**What is needed to truly PASS.** Already passes as a core-model capability; no action needed for the rung as defined.

---

## SSKΩ-7 — Locator pool + relay-fabric adapters (the load-bearing network rung)

**Original claim.** *"Locator pool + relay-fabric adapters: **real egress adapters behind the async edge, health probing**."* Self-graded **⚠️** (`spec:256`): only the funnel-DAG landed; real egress adapters/health probing *"remain out of scope (Section X — real network I/O stays the Desktop track's `ssk-netcore` responsibility)."*

**Current real status.** **NOT MET** — and this is the one rung whose own definition requires a real network/system effect. The funnel-DAG (`StitchEdge`/`LocatorGraph`/`HyperEdge`/`select_path`) exists and is tested as an in-memory algorithm, but **no real egress adapter, no health probe, and no async edge exist**. The `ssk-netadmin` adapters are **descriptor-only**: the `DataPlaneAdapter` trait has only `adapter_id()` and `describe()` — no `connect()`. The crate has **no** `tokio`/`std::net`/`rustls` dependency at all, so it cannot open a socket or resolve DNS. The responsible layer, `ssk-netcore` (`RouteExecutor` / `AdapterRuntime::connect`, Phase 3), is **absent** from the workspace, as is `ssk-capture` (Phase 4 ingress). Product-capability level 2 (type model), not level 5.

**Evidence.**
- Spec self-grade ⚠️ verbatim: `docs/OMEGA_CORE_CONFORMANCE_SPEC.md:256`.
- Adapters descriptor-only: `crates/ssk-netadmin/src/adapter.rs:37-40` (`trait DataPlaneAdapter { fn adapter_id(&self) -> &str; fn describe(&self) -> AdapterDescriptor; }`); module docstring `:3-9` (*"Adapters are descriptor-only … the actual transport is the responsibility of the caller … avoids pulling in async/tokio dependencies."*).
- No network dependencies: `crates/ssk-netadmin/Cargo.toml:15-23` (dependency set is `ssk-types`, `ssk-crypto`, `ssk-tensor`, `serde`, `serde_json`, `thiserror`, `blake3`, `hex` — no `tokio`/`std::net`/`rustls`/`hyper`/`socket2`).
- Absent crates confirmed: `ls crates/ssk-netcore` and `ls crates/ssk-capture` → No such file or directory.
- Funnel-DAG is in-memory only; production `select_egress` empties the graph: `crates/ssk-runtime/src/lib.rs:336-338`, `:348-352`.
- Daemon data plane is a mock: `crates/ssk-daemon/src/mock_dataplane.rs` (`AlwaysUpMockDataPlane::route_available` → `true` unconditionally), wired into the production binary at `crates/ssk-daemon/src/main.rs:53`; `GetStatus` hardcodes `dns_protected = false` (`supervisor.rs:251`) and adapter health `"unknown (ssk-netcore not yet integrated)"` (`:249`).
- The spec's own network doc concedes the gap: `docs/NETADMIN_SPEC.md:185-188` states a runtime `connect()` "ships in **Phase 3** as `ssk-netcore::AdapterRuntime::connect`" — i.e. does not exist yet.

### Layer responsibility — this rung is NOT core-layer, and must not be silently dropped

SSKΩ-7 does **not** belong to the decision-core layer that rungs 0–6 and 8 describe. Its definition ("real egress adapters … health probing") is a **data-plane / network-runtime** responsibility. The correct owning layer is a new crate `ssk-netcore` (Phase 3 `RouteExecutor` / `AdapterRuntime`), plus `ssk-capture` (Phase 4 ingress), integrated into `ssk-daemon`'s data plane in place of `crates/ssk-daemon/src/mock_dataplane.rs`.

This layering is honestly documented inside the tree (the core crates explicitly refuse the network responsibility: `crates/ssk-runtime/src/lib.rs:172-178` states real egress "is exclusively `ssk-netcore`'s (Desktop track's) job and never this crate's"). The problem is not the layering; it is that **the product contract depends on this layer and the layer does not exist**. `README.md:39` promises *"policy-driven, cryptographically-audited traffic routing without third-party proxy software"* and `docs/NETADMIN_SPEC.md:5-8` promises a Proxifier replacement — both are exactly SSKΩ-7. Because the rung is unmet, those product promises are unmet. It cannot be waved away as "out of scope": for the decision-core ladder it is deferrable, but for the *product contract* it is the central deliverable.

**Acceptance gate (what must be true for SSKΩ-7 to pass as the product needs it).** A running `sskd` that, on `activate`:
1. opens a real egress via a real adapter — Direct (raw TCP), SOCKS5, HTTP CONNECT, TLS tunnel, and DNS override implemented behind `DataPlaneAdapter::connect`;
2. performs real health probing of egress and reports `dns_protected`/`kill_switch` **truthfully** in `GetStatus` (not the current hardcoded `false`);
3. populates `ListRecentFlows` from real captured traffic (`ssk-capture`), replacing the current `vec![]`;
4. passes an **automated end-to-end network test** that drives a real socket egress and asserts the routing / kill-switch effect (no such test exists in the tree today).

**Missing evidence.** The entire `ssk-netcore` crate; a `RouteExecutor`/`AdapterRuntime` that opens real TCP (Direct), performs SOCKS5/HTTP-CONNECT handshakes, wraps TLS, and resolves/overrides DNS; real health probing; an async edge feature actually compiled and exercised; an integration/system test asserting a real routing/protection effect.

**Risk of a false checkmark.** Critical, at the product level. The "all met / production-ready" summary and README's "traffic routing without third-party proxy software" are **falsified** by this rung: the spec itself grades it ⚠️ and defers it to a crate that does not exist. Marking it green would present a non-functional data plane as a delivered privacy capability — the failure mode in which a user believes traffic is protected while every byte egresses unprotected.

**Status: FAIL.**

**What is needed to truly PASS.** Create `ssk-netcore` implementing `DataPlaneAdapter::connect` for Direct/SOCKS5/HTTP-CONNECT/TLS/DNS with real transport and health probing; replace `crates/ssk-daemon/src/mock_dataplane.rs` with a `RouteExecutor`-backed data plane; make `GetStatus` report real `dns_protected`/`kill_switch` and `ListRecentFlows` from `ssk-capture` ingress; add an automated integration test that drives real socket egress end-to-end and asserts the routing/kill-switch effect. Until then the rung and the network product contract remain unmet.

---

## SSKΩ-8 — Full simulation + conformance testbed

**Original claim.** *"Full simulation + conformance testbed: privacy metric tests, defensive adversary sim, all vectors."* Self-graded **✅ met** (`spec:257`).

**Current real status.** Met as an in-process model/testbed, honestly scoped. The faultscan detection taxonomy, the `LinkabilityEstimator` privacy metric with residue-visibility tests, golden/negative interop vectors, chaos drills, and the Section-W property suite all run green — but every collaborator is the deterministic abstract model or a test-double. The "adversary sim" and "privacy metrics" operate over in-memory structs, not over real traffic or a real adversary. Level 4 as a testbed artifact; it validates model invariants, not a real privacy guarantee.

**Evidence.**
- Section-W conformance bound to `LocalFiberExecutor` + `LocalOverlay` locators: `crates/ssk-runtime/tests/conformance.rs:42-132` (executor at `:60`, `:85`, `:116`, `:127`; locator kind `:22`).
- Privacy metric consumed by `PrivacyGate`: `crates/ssk-gates/src/lib.rs:301`; `ssk-privacy` `LinkabilityEstimator`.
- Chaos: `chaos_drills` CI job `.github/workflows/ci.yml:99-105` (`ssk-faultscan`); the CLI chaos runner is an explicit stub — `crates/ssk-cli/src/main.rs:1378-1398` (*"Stub runner: mimics the gate heuristic"*).
- Interop golden vectors: `ssk-interop` tests, run under `insecure-test-keys` fixed key.

**Missing evidence.** A simulation/adversary test that operates against real traffic or a real network adversary model rather than in-memory candidates; privacy metrics measured over actual routed flows (blocked by the absent data plane / SSKΩ-7).

**Risk of a false checkmark.** Medium. "✅ met" is fair for a model testbed, but "defensive adversary sim / privacy metric tests" can imply a demonstrated privacy property against a real adversary. The metrics gate an abstract `StitchCandidate`; they prove no real unlinkability.

**Status: PASS** (in-process model testbed).

**What is needed to make the privacy/adversary claims product-meaningful.** Re-run the metrics over real flows once SSKΩ-7's data plane exists; replace the CLI chaos stub with a run against the real system under test.

---

## SSKΩ-9 — Production-hardened runtime profile

**Original claim.** *"Production-hardened runtime profile: dissolution/TTL sweeps, ledger verification, deployment audit, documented limits."* Self-graded **✅ met** (`spec:258`), citing `DissolutionManager::{is_expired,sweep,finalize_expired}`, the 12-section validated config, and hash-chained ledger `verify()`.

**Current real status.** Not genuinely met; "production-hardened" is the headline overclaim on this rung. The TTL-sweep functions exist and pass a unit test but have **zero production callers** — no scheduler/daemon/CLI ever invokes `sweep`/`finalize_expired`; finalized residues land in an in-memory register with no persistence and no observer; no user can observe a sweep. Ledger verification is asymmetric (no verify for the stitch chain; the daemon's audit chain is never written, so its verify is vacuous — see SSKΩ-5). Config validation is real and strong, but the loaded config is parsed and then **discarded** (logged, never wired into the supervisor or netadmin), so it drives no runtime behavior. Deployment/packaging is not production-hardened: the release ships a **source tarball, not the built binaries**; there are no systemd/launchd units; the daemon traps only SIGINT (no SIGTERM), leaving a stale lock on service kill; and there is no cross-restart state persistence. "Documented limits" is the one honestly-satisfied sub-clause (`docs/DESKTOP_CLIENT_ARCHITECTURE.md` is a candid internal audit). Level 3–4 as isolated artifacts; not a production-hardened runtime.

**Evidence.**
- TTL sweep has no callers: `crates/ssk-tensor/src/lib.rs:211`, `:218`, `:237-259`; the identifiers appear only in their definitions, that file's `#[cfg(test)]` block (`:498-541`), and docs — no call site in `ssk-runtime`/`ssk-cli`/`ssk-daemon`/`ssk-ipc`/`ssk-netadmin`.
- Residue register is an in-memory `Vec`, no persistence: `crates/ssk-types/src/lib.rs:730-755`. (Note the in-code overclaim: the `finalize_expired` doc comment describes the residue as "hash-chained"/"auditable," yet `ResidueRegister` is neither chained nor persisted.)
- Config parsed then discarded: `crates/ssk-daemon/src/main.rs:38-53` (the loaded config is logged then dropped; `Supervisor::new` takes only an audit path + data plane, `supervisor.rs:44`). Runtime policy is hardcoded, not config-driven: `reference_policy_engine`/`reference_route_orchestrator` at `supervisor.rs:112-154`.
- Daemon never records audit (vacuous verify): no `.record()` in `supervisor.rs`; `audit_head` always `None` (`:239-243`).
- Release ships source, not binaries: `.github/workflows/release.yml:19-20` (`tar -czf … crates Cargo.toml README.md docs`; the `cargo build --release` output at `:19` is never included in `dist/`) versus the claim at `README.md:381` that it "packages platform binaries."
- No service units / SIGTERM: only `tokio::signal::ctrl_c()` at `crates/ssk-daemon/src/main.rs:71`; stale `sskd.lock` on kill (`main.rs:22-36`, `:60`). No cross-restart persistence: `supervisor.rs:45-53` always starts `Inactive` with `active_profile: None`.
- Doc self-grade "✅ met": `docs/OMEGA_CORE_CONFORMANCE_SPEC.md:258`.

**Missing evidence.** A production path that actually runs `DissolutionManager::sweep` (scheduler tick or daemon epoch advance) and a user-observable surface for residues/sweeps; a stitch-chain `verify()` and a non-vacuous daemon audit chain; config actually wired into the supervisor/netadmin so it changes runtime behavior; binary packaging (a release artifact containing `target/release/ssk` and `sskd`), systemd/launchd units, SIGTERM handling with lock cleanup, and profile persistence across restart.

**Risk of a false checkmark.** High. "Production-hardened runtime profile … ✅ met" is contradicted on every sub-clause: the TTL sweep never runs, ledger verify is asymmetric/vacuous, config is validated-then-thrown-away, and the release ships no runnable binary. Together with SSKΩ-7, this rung is the second hard falsifier of the "all met" summary.

**Status: PARTIAL.**

**What is needed to truly PASS.** Invoke `DissolutionManager::sweep` from a real driver (daemon epoch tick) and expose residues/sweeps over IPC/CLI; add a stitch-chain `verify()` and make the daemon `record()` its audit chain; wire the validated `AppConfig` into `Supervisor` and `ssk-netadmin` (retire the `reference_policy_engine` hardcode); fix `release.yml` to package the built binaries; add systemd/launchd units, SIGTERM handling with lock cleanup, and profile persistence across restart; correct the `finalize_expired` doc comment (`ssk-tensor/src/lib.rs`) that calls a non-persisted, non-chained in-memory residue "hash-chained" and "auditable." Then re-grade against "production-hardened."

---

## Cross-cutting reconciliation

**What the ladder honestly earns.** As a **decision/audit/planning core artifact**, the tree is a solid level-4 achievement: a real deterministic scheduler, a real cryptographic BCIK crossing, a genuine fail-closed 12-gate vector, an in-memory hash-chained tensor with a tested preservation theorem, a genuine re-executing replay engine, a strong fail-closed config validator, and a real local Unix-socket control plane driven cross-process by a real `sskd` in `crates/ssk-daemon/tests/round_trip.rs`. Rungs 0, 1, 3, 4, 6, and 8 are legitimately met at that core-model reading.

**Where the ladder does not reach the product contract.** The product promises (Proxifier-replacing traffic routing, DNS protection, kill-switch over real traffic, cryptographically-audited flows, installable service) all sit above the core, and they depend on rungs that are **not** met: SSKΩ-7 (FAIL — no data plane; `ssk-netcore`/`ssk-capture` absent), SSKΩ-5 (PARTIAL — transient in-memory store, no stitch-chain verify, daemon audit never written), SSKΩ-9 (PARTIAL — TTL sweep never runs, config discarded, source-only release), and SSKΩ-2 (PARTIAL — the "locator-reality check" observes no reality). The daemon's **live status output is honest** — `dns_protected=false`, `ListRecentFlows` returns `[]`, adapter health reads `"ssk-netcore not yet integrated"` — so the overclaim lives in `README.md`, `docs/NETADMIN_SPEC.md`, `docs/COMPLETION_CHECKLIST.md`, and the spec's `:39` "all met" summary, not in the running code.

**Two hard falsifiers of any "all met" reading**, both reproducible in this tree:
1. `cargo check -p ssk-core --no-default-features` → exit 101 (E0425/E0433 at `crates/ssk-core/src/connection.rs:55,78,87`), contradicting the CI-advertised no_std guarantee at `README.md:102`.
2. SSKΩ-7's own ⚠️ row at `docs/OMEGA_CORE_CONFORMANCE_SPEC.md:256`, deferring the network data plane to the absent `ssk-netcore` crate, directly contradicting the `:39` "SSKΩ-0 through SSKΩ-9 are all met" summary.

**Honest bottom line.** The correct grade for the ladder today is: six rungs PASS at the core-model level (0, 1, 3, 4, 6, 8), three PARTIAL (2, 5, 9), and one FAIL (7). The core is a real, tested, deterministic artifact; the network/privacy product capability the contract advertises is not yet delivered, and the single rung that would deliver it is unmet and deferred to code that does not exist in the workspace. The path to closing the gap is concrete and enumerated per rung above; it is primarily an integration and data-plane-construction effort (`ssk-netcore` + `ssk-capture` + wiring config/audit/dissolution into live daemon paths), not a redesign of the core.