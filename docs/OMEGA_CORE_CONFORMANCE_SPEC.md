# ScorpioSync-Kaleidoscorp Ω — Core Conformance Consolidation Spec

> Status: **Architecture specification** (no code in this document).
> Scope: Close the gap between the repository's *decision-modeling core* crates
> (`ssk-types`, `ssk-core`, `ssk-scheduler`, `ssk-identity`, `ssk-locator`, `ssk-stitch`,
> `ssk-bcik`, `ssk-gates`, `ssk-tensor`, `ssk-focus`, `ssk-replay`, `ssk-faultscan`,
> `ssk-privacy`, `ssk-crypto`, `ssk-config`, `ssk-runtime`) and the literal, formal target
> defined by `ScorpioSync-Kaleidoscorp-Omega-Rust-Master-Spec.pdf` ("Master Specification
> Layer Ω+1 (Implementation Normalization)", Sebastian Klemm, 3 Jul 2026) — hereafter
> **"the PDF"** — so the system can genuinely claim conformance levels **SSKΩ-4 through
> SSKΩ-9** per the PDF's own staged ladder (its Chapter 22).
>
> Every statement about the **current** state of the repository is traced to a concrete file
> and line number, re-verified directly against the source at the time this document was
> written. Every statement about the **target** state is either a verbatim Rust signature
> quoted from the PDF, or explicitly marked as this document's own design decision where the
> PDF is silent (e.g. crate placement). The two are never mixed.
>
> This document does **not** touch, redesign, or duplicate `docs/DESKTOP_CLIENT_ARCHITECTURE.md`
> (the daemon/IPC/data-plane product track, already implemented). See Section C.

---

## Legend — implementation status classification

Reused from `docs/DESKTOP_CLIENT_ARCHITECTURE.md` for consistency:

| Tag | Meaning |
|-----|---------|
| **[1] Implemented** | Real, exercised by tests, does the work it claims. |
| **[2] Partial** | Real logic present but the shape/semantics diverge from the PDF's definition. |
| **[3] Name-only** | The identifier exists (a type, a field, a variant) but its behavior does not implement what the PDF specifies for that name. |
| **[4] Absent** | Nothing in the codebase corresponds to this PDF object. |

---

## A. Executive Diagnosis

The repository's decision-modeling core is a real, tested, deterministic MVP that implements
the *shape* of the PDF's pipeline (scheduler tick → identity orbit → locator selection →
BCIK crossing → twelve-gate vector → conditional tensor append → replay manifest) but
**not its substance** in most of the interior objects. Concretely:

- The **foundation layer** (Chapter 3 of the PDF: `content_id!`, sealed `CoreObject` with
  `object_kind()`/`residue_policy()`, the `Connection<S>` typestate, `SecretBytes`, the
  18-variant `FaultKind` vocabulary) is now **implemented as scaffolding (Phase 0, done)**:
  `Digest` is content-addressable (`[u8; 32]`, hex-serde-compatible), `CoreObject` has real
  `object_kind()`/`residue_policy()` impls, `Connection<S>`'s typestate machine is real and
  compile-time enforced (its five transition bodies are deliberately stubbed pending later
  phases), `SecretBytes` is real, and the 18-variant `FaultKind` enum exists. What remains
  absent is the *migration* of existing ids/errors onto this scaffolding, and the real
  transition-body logic — both tracked phase-by-phase in Section V.
- The **domain model** (Chapter 4: full `CoreNode`/`MirrorFacet` fields, cryptographic
  `MirrorOrbit`, `birefract()`/`IdentityRay`/`LocatorRay`, 9-variant `LocatorKind`) is
  **present in miniature** [2]/[3] — `CoreNode` has 4 of 7 spec fields, `MirrorFacet` has 3 of
  11, `Orbit::derive/recover` is string-formatting rather than content-addressed, and
  `birefract()` does not exist — the split into an identity ray and a locator ray never
  happens; `ssk-stitch::from_intent` goes straight from `ConnectionIntent` to `StitchCandidate`.
- The **locator/funnel-DAG model** (Chapter 6: `LocatorAdapter`, `LocatorPool` trait with
  `claims_external_plurality()`, `StitchEdge`/`LocatorGraph`/`HyperEdge`) is **absent** [4] —
  `LocatorPool` is a concrete struct, not a trait, and never claims or disclaims plurality.
- The **Hypertoroidal Scheduler** (Chapter 7) is **partially real** [2] — the fixed-point
  toroidal phase math is faithfully implemented, but `SchedulerMode::Seeded` and
  `visible()`'s toroidal-distance predicate do not exist; the `seeded: bool` flag is stored
  and never read.
- The **Projective Connection Hypercube and Gabriel Constraint Cells** (Chapters 8, 10) are
  **entirely absent** [4] — there is no 9-axis projection type anywhere in the tree.
- The **BCIK crossing kernel** (Chapter 9) is **name-only** [3] — `cross()` exists and returns
  a `CrossOutcome`, but `Closed` carries no payload (the PDF's `BcikStitch` does not exist),
  and the crossing condition is two hardcoded booleans, not a real seam/boundary evaluation.
- The **gate system** (Chapter 11) is **structurally present, substantively thin** [2] — all
  twelve `GateId` variants exist and are dispatched, but eleven of the twelve checks are
  single-boolean-flag reads (the PDF specifies richer per-gate evidence, e.g. `CapabilityGate`
  checking a real witness's scope/epoch/expiry). `GateVector::evaluate` also **contradicts**
  the PDF's own pseudocode by `break`-ing on the first Quarantine/Reject instead of evaluating
  all twelve gates.
- The **capability and crypto layer** (Chapter 5) has real `SignatureProvider`/`AeadProvider`
  implementations (ed25519, ChaCha20-Poly1305 — landed in a prior implementation pass) but
  **no `CapabilityWitness` struct anywhere** [4] — `capability_witness` is a bare `bool`, and
  `KeyAgreementProvider`/`CapabilityWitnessProvider` remain unimplemented traits.
- The **persistent Stitch Tensor** (Chapter 12) has real hash-chained append-only storage with
  disk persistence (landed in the same prior pass), but **no `apply_sorted`, no
  `StorageBackend` trait, no `StitchGraph`** [3] — the tensor-preservation theorem is provable
  today only informally (one unit test), not as a typestate-enforced compile-time guarantee.
- **Concave Reanalysis Focus** (Chapter 13) is a single 8-line boolean function [3] — no
  `FocusEngine`, `FocusReport`, or `CoreSessionClass` exist.
- The **privacy/linkability model** (Chapter 15) is a single heuristic function [3] — no
  `LinkabilityEstimator` trait, `AdversaryModel` enum, or `LinkabilityReport` struct exist.
- **Faultscan** (Chapter 17) is real and tested, but is a **different concern with the same
  name** [3] — the PDF's `FaultKind` is an 18-variant *detection* taxonomy behind a
  `Faultscan::scan()` trait; the codebase's `FaultKind` is a 6-variant *chaos-injection
  selector* with an unrelated API (`inject_fault`/`run_drill`/`run_playbook`).
- The **replay engine** (Chapter 16.3) is real but **shallow** [2] — it diffs two
  already-computed `RuntimeOutcome`s for equality; it does not "re-execute the decision core"
  as the PDF's trait contract requires, because no shared, re-invocable pipeline function
  exists outside `ssk-runtime`'s own method body.
- The **runtime pipeline and outcome type** (Chapter 14) is a real, deterministic 5-step
  pipeline, but its outcome is a flat `RuntimeOutcome` struct, not the PDF's 3-variant
  `RunOutcome`, and it is missing four named pipeline stages the PDF's spine requires
  (`PchPlacement`, `GabrielEvaluation`, explicit `CapabilityCheck`, `LinkabilityResidue`).
- The **configuration model** (Chapter 21) covers roughly 4 of the PDF's ~30 fields across its
  12 top-level YAML sections [3] — today's `AppConfig` has `version`/`policy`/`runtime`/
  `interop`; the PDF's schema additionally specifies `locator_plane`,
  `projective_connection_hypercube`, `hypertorus`, `bcik`, `capabilities`, `privacy`, `gates`,
  `replay`, `ledger`, `dissolution`.

**Honest conformance ceiling at the time of writing: SSKΩ-2, bordering SSKΩ-3.** The typed model,
deterministic core, and mirror-facet orbit with a locator pool existed (SSKΩ-0/1/2's
requirements), but SSKΩ-2's own "locator-reality checks" were not real, and SSKΩ-3's requirement
that "every crossing carries seam, boundary, gate, trace, replay" was not met. **Update — Phases 1
and 2 complete:** SSKΩ-1/2 are now met to the letter (`HypertoroidalScheduler`'s real
`SchedulerMode`/`visible()`; content-addressed `MirrorOrbit`; real
`LocatorPool::claims_external_plurality()`). SSKΩ-3's crossing now genuinely carries seam
(`SeamWitness`, `HashProvider`-backed), boundary (`BoundaryRecord`), trace, and replay
(`BcikStitch`'s full field set, Section J) — the one field still not populated is `gate_report`
(always `None` today); wiring `GateVector`'s output back into `BcikStitch` remains open for a
later phase. **Update — Phase 3 complete:** SSKΩ-4 is now met — the gate system overhaul (Section
K, twelve real gate structs, no early-`break`) and the Projective Connection Hypercube (Section I,
real 9-axis `Hypercube` plus the Gabriel Constraint Cells) both landed, tested, and verified.
**Update — Phase 4 partial:** the persistent Stitch Tensor itself (Section M — real
`StitchTensor`/`apply_sorted`/`StorageBackend`/`StitchGraph`) is now real and tested in
`ssk-tensor`; wiring it into `ssk-runtime`'s live pipeline and into
`Connection<GatePassed>::materialize` remains deferred (see below). **Update — Phase 5 mostly
complete:** SSKΩ-6's `FocusEngine`/`FocusReport` (Section N) and a genuinely re-executing
`ReplayEngine` (Section Q, via a new shared `ssk_runtime::execute_pipeline`) both landed, tested,
and verified — `LinkabilityEstimator`/`AdversaryModel`/`LinkabilityReport` (Section O) landed
alongside as N's own dependency. `RunOutcome` (Section R) exists as a real, tested type but is
deliberately **not wired** into any live call site: a genuine `Pass` variant needs real
`Response` evidence from a `FiberExecution`/`ResponseCapture` pipeline stage, and neither stage
exists anywhere in this workspace — fabricating that evidence to force the wiring would trade
honesty for a checkbox, so this document declines to. **Update — Phase 6 done (funnel-DAG
only):** SSKΩ-7's `StitchEdge`/`LocatorGraph`/`HyperEdge`/`select_path` (Section G.2) landed and
tested in `ssk-locator`, generic over a new dependency-inverted `PathProjectionCheck` trait
rather than the real `Hypercube` (same crate-cycle constraint as Phases 3-5, disclosed inline);
real egress adapters and health probing remain out of scope per Section X. This document designs
the closing architecture for SSKΩ-8/9 (remaining), plus Section R's unfinished wiring and G.2's
undone `Hypercube` bridging.

---

## B. Current Implementation Inventory

Evidence re-verified directly against source at the time of writing (not carried over from an
earlier pass without recheck).

| Area | Tag | Evidence (file:line) | PDF ref |
|------|-----|----------------------|---------|
| Content-addressed ids / `content_id!` | **[1] Phase 0 done** | `Digest` is now `[u8; 32]`-backed with hex-string serde (`crates/ssk-types/src/lib.rs`); `content_id!` macro exists and is determinism-tested. `CoreId`/`RunId`/etc. deliberately **not yet migrated** off `id_type!`'s opaque-string form — each migrates only once its owning object carries real canonical content (Section V) | Ch. 3.1 |
| Sealed `CoreObject` (`object_kind`/`residue_policy`) | **[1] Phase 0 done** | `crates/ssk-core/src/lib.rs` — `CoreObject` (renamed from `SealedCoreObject`, sealed via `mod sealed`) now has real `object_kind()`/`residue_policy()` impls for `CoreNode`/`MirrorFacet` | Ch. 3.2 |
| `Connection<S>` typestate | **[2] Phase 0 skeleton** | `crates/ssk-core/src/connection.rs` — phantom-state machine is real and compile-time enforced (proven by two `trybuild` compile-fail fixtures); all five transition bodies are deliberately stubbed pending their owning phase (Section V) | Ch. 3.3 |
| `SecretBytes`/zeroize | **[1] Phase 0 done** | `crates/ssk-crypto/src/lib.rs` — real zeroize-wrapped, redacted-`Debug` type; `zeroize` promoted to a direct dependency | Ch. 3.4 |
| Unified `FaultKind` vocabulary | **[2] Phase 0 partial** | `crates/ssk-types/src/lib.rs` — the real 18-variant enum now exists; no crate's public API returns it yet (that migration is Phases 1-4's job, Section E.5/T) | Ch. 3.5 |
| `CoreNode` full fields | **[1] Phase 1 done** | `crates/ssk-types/src/lib.rs` — all 7 fields present (`id, canonical, signature, policy_root, replay_root, audit_root, closure`) | Ch. 4.1 |
| `MirrorFacet` full fields | **[1] Phase 1 done** | `crates/ssk-types/src/lib.rs` — all 11 fields present (`id, core, phase, orientation, sector, key_ctx, session, policy, trace, boundary, residue`) | Ch. 4.1 |
| Real `MirrorOrbit::derive/recover` | **[1] Phase 1 done** | `crates/ssk-core/src/lib.rs` — `MirrorOrbit::derive` computes `FacetId` from the canonical bytes of `(core id, seed, phase, sector)`; `recover` re-derives and compares, total over facets from the same orbit | Ch. 4.1 |
| `birefract()`/`IdentityRay`/`LocatorRay` | **[1] Phase 1 done** | `crates/ssk-core/src/lib.rs` — real, tested function; the two ray types have no `From`/`Into` between them | Ch. 4.2 |
| 9-variant `LocatorKind`/`LocatorFacet` | **[1] Phase 1 done** | `crates/ssk-types/src/lib.rs` — all 9 variants; `LocatorFacet` carries the full field list plus two disclosed Phase-1 bridge fields (`trusted`/`risk_score`) preserving today's gate checks until Phase 3 rewires them | Ch. 4.3 |
| `LocatorAdapter`/`LocatorPool` trait + `claims_external_plurality()` | **[1] Phase 1 done** | `crates/ssk-locator/src/lib.rs` — real traits; `StaticLocatorPool` implements both, with `claims_external_plurality()` genuinely counting distinct live endpoints (tested false-for-one, false-for-shared-endpoint, false-for-non-live, true-for-two-distinct-live) | Ch. 6.2 |
| `StitchEdge`/`LocatorGraph`/`HyperEdge`/`select_path` | **[2] Phase 6 done (funnel-DAG only)** | `crates/ssk-types/src/lib.rs` (data types) + `crates/ssk-locator/src/lib.rs` (`select_path`, BFS over edges/hyperedges) — real and tested; no `Hypercube` wiring (dependency-inversion trait `PathProjectionCheck` instead, disclosed) and no real network egress adapters (stays `ssk-netcore`'s job, Section X) | Ch. 6.3-6.4 |
| `SchedulerMode`/`SchedulerSeed`/`visible()` | **[1] Phase 1 done** | `crates/ssk-scheduler/src/lib.rs` — renamed `HypertoroidalScheduler`; `Seeded` mode genuinely jitters phase advancement via a `rand_pcg`-seeded PRNG keyed by `(seed, tick count)`; `visible()` implements the literal toroidal-distance formula, tested including wraparound | Ch. 7.2 |
| Projective Connection Hypercube | **[1] Phase 3 done** | `crates/ssk-gates/src/pch.rs` — real `Axis`/`Projection`/`Hypercube`; nine real per-axis projectors, `check()` returns `Pass`/`Hold`/`Fail` per the ch. 8.2 invariant (`OverBudget` holds, all else fails); `ProtocolProjector` honestly always-`Ok` (no fiber-invariant model yet) | Ch. 8 |
| Gabriel Constraint Cells | **[1] Phase 3 done** | `crates/ssk-gates/src/gabriel.rs` — real `CellRole`/`CellVerdict`/`ConstraintCell`/`GabrielFilm`; nine real per-role cells, `evaluate_all()` tested (intact-candidate all-`Propose`, missing-capability `Reject`, high-risk `Quarantine`); `ProtocolCell` honestly always-`Propose` for the same reason | Ch. 10 |
| `BcikStitch` payload | **[1] Phase 2 done** | `crates/ssk-types/src/lib.rs` — real struct with all ch. 9.1 fields; `CrossOutcome::Closed(BcikStitch)` carries it | Ch. 9.1 |
| Real BCIK crossing kernel | **[2] Phase 2 partial** | `crates/ssk-bcik/src/lib.rs` — real `Bcik<'p>` struct (`HashProvider`-backed seam witness, `ResidueRegister`), tested (closed-stitch fields populated, residue recorded on open crossing); closure condition is still `candidate.seam_ok && candidate.boundary_complete` — real per-fiber invariant checking is Phase 3's `FiberGate` job | Ch. 9.1 |
| Full `BoundaryResidue` (severity/origin/open_obligation) | **[1] Phase 2 done** | `crates/ssk-types/src/lib.rs` — all ch. 9.2 fields present via `BoundaryResidue::new(...)`, wired at every construction site | Ch. 9.2 |
| `ResidueRegister` | **[1] Phase 2 done** | `crates/ssk-types/src/lib.rs` — real `emit()`/`open_obligations()`/`entries()`; `Bcik` owns one and emits into it on every open crossing | Ch. 9.2 |
| Twelve real per-gate evaluators | **[1] Phase 3 done** | `crates/ssk-gates/src/lib.rs` — twelve distinct gate structs (`CoreGate`, `MirrorGate`, `LocatorGate`, `BcikGate`, `HypercubeGate`, `CapabilityGate`, `FiberGate`, `PrivacyGate`, `BoundaryGate`, `FocusGate`, `ReplayGate`, `DissolutionGate`); `MirrorGate` drives real `MirrorOrbit::recover`, `BcikGate` drives real `Bcik::cross`, `HypercubeGate` drives the new `pch::Hypercube::check`, `CapabilityGate` checks real witness expiry/scope, `PrivacyGate` uses real `ssk_privacy::linkability_score` | Ch. 11.2 |
| `GateVector::evaluate` — all-gates-evaluated | **[1] Phase 3 done** | `crates/ssk-gates/src/lib.rs` — both early `break`s removed; `all_twelve_gates_are_evaluated_even_after_an_early_reject` proves every gate fires exactly once via a counting spy, matching the PDF's own no-break pseudocode | Ch. 11.2 |
| `GateProfile` richer fields | [2] | `crates/ssk-config/src/lib.rs:30-46` — only `order`, `fail_closed`; missing `thresholds, required_evidence, failure_policy, hold_policy, pass_policy` | Ch. 11.3 |
| `CapabilityWitness` struct | **[1] Phase 2 done** | `crates/ssk-types/src/lib.rs` — real struct with all ch. 5.2 fields; `StitchCandidate`/`ConnectionIntent.capability_witness: bool` replaced by `capability: Option<CapabilityWitness>` | Ch. 5.2 |
| `CapabilityWitnessProvider`/`KeyAgreementProvider` impls | **[1] Phase 2 done** | `crates/ssk-crypto/src/lib.rs` — `Ed25519CapabilityWitnessProvider` (`WitnessKind::Signature`, real issue/verify with scope+expiry checks, tested incl. tamper/expiry/scope-mismatch/wrong-issuer); `X25519KeyPair` real `KeyAgreementProvider` (zero new deps — `x25519-dalek` was already an unused optional dependency) | Ch. 5.1 |
| `StitchTensor`/`apply_sorted`/`StorageBackend` | **[2] Phase 4 done (ssk-tensor)** | `crates/ssk-tensor/src/lib.rs` — real `StitchTensor{graph, head, backend}`, `apply_sorted` (deterministic `(epoch, StitchId)` ordering, hash-chained `StitchTensorEntry`s), `StorageBackend` (supertrait of `GenericLedgerBackend<StitchTensorEntry>`, blanket-implemented), real `StitchGraph`; `ssk-runtime`'s live pipeline still writes the older flat `TensorEntry` — wiring it to `StitchTensor` is deferred to Phase 5 alongside the `RunOutcome`/pipeline-stage rework (Section R), since that is where the gate witness starts carrying a real `BcikStitch` forward instead of discarding it | Ch. 12.1-12.2 |
| `FocusEngine`/`FocusReport`/`CoreSessionClass` | **[1] Phase 5 done** | `crates/ssk-focus/src/lib.rs` — real `FocusEngine::reanalyze` over `Response` evidence, `CoreSessionClass`/`FocusVerdict`/`FocusReport`; the original `refocuses()` boolean check is kept unchanged as `FocusGate`'s real backing check (a different, faster, gate-time concern than session reconstruction) | Ch. 13.1 |
| `LinkabilityEstimator`/`AdversaryModel`/`LinkabilityReport` | **[1] Phase 5 done** | `crates/ssk-privacy/src/lib.rs` — real trait/enum/struct; `HeuristicLinkabilityEstimator` wraps the original heuristic, declaring `AdversaryModel::PartialNetworkObserver`; `linkability_score()` kept unchanged for `PrivacyGate`'s existing call site | Ch. 15.3 |
| Real re-executing `ReplayEngine` | **[1] Phase 5 done** | `crates/ssk-replay/src/lib.rs` — `ReplayEngine::replay` now re-executes the decision core itself (via `ssk_runtime::execute_pipeline`, Section Q's shared-pipeline extraction) and diffs the fresh result against the manifest's `trace_head`/`expected_outcome_digest`, rather than being handed two pre-computed outcomes | Ch. 16.3 |
| 18-variant `FaultKind` + `Faultscan` trait | [3] | `crates/ssk-faultscan/src/lib.rs:16-29` — actual enum has 6 chaos-injection variants (`SignatureCorruption, CapabilityWithdrawal, TtlExpiry, ReplayDrift, AttestationFailure, LocatorUntrust`), API is `inject_fault`/`run_drill`/`run_playbook`, structurally unrelated to the PDF's detection taxonomy | Ch. 17.1 |
| 3-variant `RunOutcome` | **[2] Phase 5 partial** | `crates/ssk-runtime/src/lib.rs` — real `RunOutcome{Pass, HoldRefine, DissolveRejectQuarantine}` and a tested `RunOutcome::resolve(gate_report, ...)` mapping all five `GateOutcomeKind` values correctly; lands in `ssk-runtime` rather than `ssk-types` (disclosed placement correction — `Pass.focus: FocusReport` means it can only live where both `ssk-focus` and `ssk-types` are already dependencies, and `ssk-types` cannot depend on `ssk-focus` without a cycle). **Not yet wired** into any live call site: a real `Pass` needs a genuine `FocusReport`, which needs real `Response` evidence from a `FiberExecution`/`ResponseCapture` stage that does not exist yet. `RuntimeOutcome` (the older flat struct) is unchanged and still what `Runtime::run_once_with_context` returns | Ch. 14.2 |
| Full runtime pipeline stages | [2] | `crates/ssk-runtime/src/lib.rs` — still 5 traced steps (`Scheduler, Orbit, Locator, Bcik, Gates`) inside the newly-extracted `execute_pipeline`; PDF's spine (Ch. 14.1) names 20 stages including `PchPlacement, GabrielEvaluation, CapabilityCheck, LinkabilityResidue`. Not addressed this phase: splitting these out would require breaking `GateVector::evaluate` (currently one atomic call producing one `GateReport`) into separately-traceable per-check stages | Ch. 14.1 |
| 12-section config schema | [2] | `crates/ssk-config/src/lib.rs:108-114` — `AppConfig{version, policy, runtime, interop}` covers roughly 4 of ~30 fields across the PDF's 12 sections | Ch. 21 |

---

## C. Relationship to Other Documents

- **`docs/DESKTOP_CLIENT_ARCHITECTURE.md`** owns turning the core into a *product*: the daemon
  (`ssk-daemon`), IPC (`ssk-ipc`), a real network data plane (`ssk-netcore`, Phase 3, not yet
  built), OS traffic ingress (`ssk-capture`, Phase 4, not yet built), and a v3
  *product/profile* config schema. That work is separate and already partly implemented
  (Phases 1-2 of that document are done). **This document never touches those crates or that
  config schema**, and this document's own locator-adapter work (Section G) stays strictly
  non-network — see Section X.
- **This document** owns making the pure decision-modeling core (the crates listed in the
  header) a literal, testable implementation of the PDF's Chapters 3-21. The Desktop doc's own
  Section E.1 calls this core "the control-plane brain" and explicitly reuses it without ever
  redefining it — this document is what makes that brain match its own formal specification.
- **`ssk-config` dual ownership.** Both efforts touch `ssk-config`, for different reasons: the
  Desktop doc's Section I wants a v3 *product/profile* schema (`AppConfigV3` — profiles,
  adapters, chains, app rules, kill-switch); this document's Section S wants the PDF's ch.21
  *core policy* schema (locator_plane, PCH, hypertorus, bcik, capabilities, privacy, gates,
  replay, ledger, dissolution). **Resolution:** this document's schema additions land under a
  distinct type, not `AppConfigV3` — see Section S for the exact naming decision. The two
  schemas are sibling concerns inside the same crate, never merged into one type.
- **`docs/AGENT_IMPLEMENTATION_PROMPT.md`** is scoped to the Desktop track's Phase 1→2 and is
  **not edited** by this document. A companion prompt file,
  `docs/OMEGA_AGENT_IMPLEMENTATION_PROMPT.md`, is added alongside it (Section Y), scoped to
  this document's own phases.

---

## D. Conformance Target Definition

Verbatim from the PDF, Chapter 22 ("Conformance is staged... a build may claim level *k* only
if all tests for levels 0..*k* pass"):

| Level | PDF Requirement | Current status |
|-------|-----------------|-----------------|
| SSKΩ-0 | Typed model: `ssk-types`/`ssk-core` compile; Core, Identity Plane, Locator Plane exist and are separately typed. | ✅ met |
| SSKΩ-1 | Deterministic core + scheduler: fixed-point phase, deterministic tick, replayable phase selection. | ✅ met |
| SSKΩ-2 | Mirror-facet orbit + locator pool with real typing and locator-reality checks. | ✅ met (Phase 1: content-addressed `MirrorOrbit`, real `claims_external_plurality()`) |
| SSKΩ-3 | BCIK `StitchCandidate` pipeline: every crossing carries seam, boundary, gate, trace, replay. | ⚠️ seam/boundary/trace/replay are real (Phase 2); `gate_report` is still always `None` — real per-gate evidence is Phase 3 |
| SSKΩ-4 | Gate vector + boundary residues: twelve gates, fail-closed, typed residues, PCH projection checks. | ✅ met (Phase 3: twelve real gate structs, no early-break, typed `ResidueKind` on every fail path, `HypercubeGate` drives the real 9-axis PCH) |
| SSKΩ-5 | Persistent Stitch Tensor + audit: hash-chained append, storage backends, tensor-preservation theorem tested. | ⚠️ `ssk-tensor`'s real `StitchTensor`/`apply_sorted`/`StorageBackend` landed (Phase 4), hash-chained and tested (including the empty-`Vec`-preserves-the-tensor case); not yet wired into `ssk-runtime`'s live pipeline (Phase 5), so the theorem is not yet provable end-to-end through the actual runtime driver |
| SSKΩ-6 | Concave Reanalysis Focus + replay: class reconstruction, replay determinism harness green. | ⚠️ real `FocusEngine`/`FocusReport` (Phase 5) and a genuinely re-executing `ReplayEngine` (Phase 5) both landed and tested; the 3-variant `RunOutcome` exists but is not wired into any live pipeline call site (needs a real `FiberExecution`/`ResponseCapture` stage that doesn't exist yet) |
| SSKΩ-7 | Locator pool + relay-fabric adapters: real egress adapters behind the async edge, health probing. | ⚠️ funnel-DAG (`StitchEdge`/`LocatorGraph`/`HyperEdge`/`select_path`, Phase 6) landed and tested; real egress adapters/health probing behind the `async-edge` feature remain out of scope (Section X — real network I/O stays the Desktop track's `ssk-netcore` responsibility) |
| SSKΩ-8 | Full simulation + conformance testbed: privacy metric tests, defensive adversary sim, all vectors. | ❌ absent |
| SSKΩ-9 | Production-hardened runtime profile: dissolution/TTL sweeps, ledger verification, deployment audit, documented limits. | ❌ absent (TTL is a bare `==0` check, no sweeping) |

**Target of this document: close SSKΩ-3 through SSKΩ-9**, in the phase order of Section V.

---

## E. Foundation Layer

**PDF ref: Ch. 3.** Lands in `ssk-types` (ids, `FaultKind`) and `ssk-core` (`CoreObject`,
`Connection<S>`); `SecretBytes` lands in `ssk-crypto` (co-located with key material).

### E.1 Content-addressed ids

PDF (Ch. 3.1, verbatim macro-invocation pattern):

```rust
content_id!(CoreId);      // canonical client core
content_id!(FacetId);     // mirror facet
content_id!(LocatorId);   // locator facet
content_id!(StitchId);    // BCIK stitch
content_id!(EdgeId);      // explicit stitch edge
content_id!(CapabilityId);// capability witness
content_id!(RunId);       // one runtime execution
content_id!(TraceId);     // trace record
content_id!(ResidueId);   // residue register entry
content_id!(EpochId);     // scheduler epoch
```

> "An identifier is derived only from the canonical serialization of the object it names. Two
> runs that produce the same canonical object produce the same id."

**Current:** `id_type!` (`crates/ssk-types/src/lib.rs:22-42`) wraps an opaque `Id(String)` —
callers choose the string; nothing is derived from content.

**Design:** `Digest` becomes `Digest([u8; 32])` and a new `content_id!` macro derives an id via
`HashProvider::digest(canonical_bytes(&object))`, reusing the already-real
`ssk_types::canonical_bytes`/`digest_of` (`crates/ssk-types/src/lib.rs:370-388`, CBOR via
`ciborium`, already a workspace dependency). **Breaking**, but keep `serde` output as a hex
string so the on-disk JSON ledger format used by `GenericFileLedgerBackend` does not need a
migration — only the in-memory representation changes. Foundational; land first (Phase 0)
since every later struct (`BcikStitch`, `CapabilityWitness`, `StitchEdge`) is specified in
terms of these ids.

### E.2 Sealed `CoreObject`

PDF (Ch. 3.2, verbatim):

```rust
mod sealed { pub trait Sealed {} }
/// Only foundation types implement `CoreObject`; downstream crates cannot.
pub trait CoreObject: sealed::Sealed {
    fn object_kind(&self) -> ObjectKind;
    fn residue_policy(&self) -> ResiduePolicy;
}
```

**Current:** `SealedCoreObject` (`crates/ssk-core/src/lib.rs:28-36`) is an empty marker trait
with the identical sealing pattern already in place, but zero methods.

**Design:** additive — extend the existing trait with `object_kind()`/`residue_policy()`; add
`ObjectKind`/`ResiduePolicy` enums to `ssk-types`. Every public foundation type gains an impl:
`CoreNode`, `MirrorFacet`, and — once they exist — `BcikStitch`, `StitchTensorEntry`,
`CapabilityWitness`, `LocatorFacet`, `StitchEdge`.

### E.3 `Connection<S>` typestate

PDF (Ch. 3.3, verbatim — this is the central sequencing anchor for the whole document):

```rust
use core::marker::PhantomData;
pub struct Intent;
pub struct Canonical;
pub struct Split;
pub struct Placed;
pub struct GatePassed;
pub struct Materialized;
pub struct Connection<S> { inner: ConnectionInner, _s: PhantomData<S> }

impl Connection<Intent> {
    pub fn canonicalize(self, c: &CoreCanonicalizer) -> Result<Connection<Canonical>, FaultKind> { /* ... */ }
}
impl Connection<Canonical> {
    pub fn birefract(self, p: &Policy) -> Result<Connection<Split>, FaultKind> { /* ... */ }
}
impl Connection<Split> {
    pub fn place(self, cube: &Hypercube, theta: &PhaseVector) -> Result<Connection<Placed>, FaultKind> { /* ... */ }
}
impl Connection<Placed> {
    /// Only a `Placed` connection can be gated; only a `GatePassed` connection
    /// can be materialized. Enforced at compile time.
    pub fn gate(self, gv: &GateVector, p: &Policy) -> GateOutcome<Connection<GatePassed>> { /* ... */ }
}
impl Connection<GatePassed> {
    pub fn materialize(self, tensor: &mut StitchTensor) -> Result<Connection<Materialized>, FaultKind> { /* ... */ }
}
```

> **Typestate guarantee:** `StitchTensor::materialize` is reachable only from
> `Connection<GatePassed>`. There is no public path from `Placed` or `Split` to a tensor
> mutation. This makes fail-closed materialization a property of the API shape, not merely of
> the runtime logic.

**Current:** absent entirely.

**Design:** land in `ssk-core::connection`, additive new type. Its transition method *bodies*
depend on later sections (`canonicalize` needs a `CoreCanonicalizer`; `birefract` needs
Section F.2; `place` needs Section I's `Hypercube`; `gate` needs Section K; `materialize`
needs Section M). Phase 0 lands the skeleton with stub bodies that return
`FaultKind::ConfigInvalid`-shaped placeholders; each later phase fills in exactly one
transition once its dependency closes (Section V maps this precisely). A `trybuild`
compile-fail test proves the guarantee holds at compile time, not just at runtime — this is
the literal Phase 0 acceptance criterion (Section W).

### E.4 Secrets and zeroization

PDF (Ch. 3.4, verbatim):

```rust
use zeroize::{Zeroize, ZeroizeOnDrop};
#[derive(ZeroizeOnDrop)]
pub struct SecretBytes(Vec<u8>);
impl core::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecretBytes(<redacted>)")
    }
}
```

**Current:** absent; `zeroize` is only a transitive dependency (via `ed25519-dalek`/
`x25519-dalek`'s own `zeroize` feature). **Design:** additive, land in `ssk-crypto`; promote
`zeroize` to a direct dependency there.

### E.5 Unified error/fault vocabulary

PDF (Ch. 3.5, verbatim): "Every fallible foundation operation returns `Result<T, FaultKind>`
where `FaultKind` is the crate-local slice of the global Fault taxonomy (Chapter 17)."

**Current:** `ConfigError`, `TensorError`, `RuntimeError`, `TypeError` are independent
`thiserror` enums, one per crate (confirmed, no shared vocabulary).

**Design:** `FaultKind` (the PDF's 18-variant taxonomy, quoted in full in Section P) lands in
`ssk-types` as the canonical vocabulary. Foundation crates' *public trait-boundary* methods
(`ssk-core`, `ssk-bcik`, `ssk-gates`, `ssk-tensor`, `ssk-focus`) migrate to return `FaultKind`
directly. Crates with genuine I/O-shaped errors (`ssk-tensor`'s file errors, `ssk-config`'s
parse errors) **keep** their richer local error enum for internal use, but add
`impl From<TensorError> for FaultKind` (→ `StorageFailure`) and
`impl From<ConfigError> for FaultKind` (→ `ConfigInvalid`) bridges at the boundary — this
resolves the tension between "one shared vocabulary" (PDF's requirement) and "don't destroy
useful local error detail" (a real, non-negotiable engineering need).

---

## F. Domain Model

**PDF ref: Ch. 4.** Lands in `ssk-types` (structs) and `ssk-core` (`MirrorOrbit`, `birefract`).

### F.1 Full `CoreNode`/`MirrorFacet` fields

PDF (Ch. 4.1, verbatim):

```rust
/// The canonical client identity. Never exposed as a public locator.
#[derive(Clone, Serialize, Deserialize)]
pub struct CoreNode {
    pub id: CoreId,
    pub canonical: CanonicalForm,     // xc = Can(xc) must hold
    pub signature: CoreSignature,     // over canonical form
    pub policy_root: PolicyRootRef,
    pub replay_root: ReplayRoot,
    pub audit_root: AuditRoot,
    pub closure: ClosureState,
}
/// A projection of exactly one CoreNode. Ephemeral, identity-side only.
#[derive(Clone, Serialize, Deserialize)]
pub struct MirrorFacet {
    pub id: FacetId,
    pub core: CoreId,           // the single core this facet belongs to
    pub phase: PhaseVector,     // theta in T^n
    pub orientation: Orientation,
    pub sector: Sector,
    pub key_ctx: KeyContextRef, // ephemeral, zeroized material by ref
    pub session: SessionId,
    pub policy: PolicyId,
    pub trace: TraceId,
    pub boundary: BoundaryRef,
    pub residue: ResidueRef,
}
```

**Current:** `CoreNode` has `id, canonical_name, policy_root, signature_ok` (4 of 7);
`MirrorFacet` has `facet_id, core_id, sector, replay_root` (3 of 11, plus a non-spec
`replay_root`) — `crates/ssk-types/src/lib.rs:52-65`.

**Design: breaking** field additions in `ssk-types`. New opaque newtypes (`KeyContextRef`,
`BoundaryRef`, `ResidueRef`, `SessionId`, `Orientation`, `CanonicalForm`, `CoreSignature`,
`ClosureState`) so every crate that constructs a `CoreNode`/`MirrorFacet` literal (`ssk-bcik`
tests, `ssk-gates` tests, `ssk-runtime`, `ssk-stitch`) isn't blocked on unrelated subsystems
being real yet — the new fields can carry cheap, honest placeholder values until their owning
sections land.

### F.2 Real `MirrorOrbit`

PDF (Ch. 4.1, verbatim):

```rust
/// Deterministic set of facets derived from one core at a phase state.
pub struct MirrorOrbit<'c> { core: &'c CoreNode, seed: OrbitSeed }
impl<'c> MirrorOrbit<'c> {
    pub fn derive(&self, phase: &PhaseVector, sector: Sector) -> MirrorFacet { /* ... */ }
    pub fn recover(&self, facet: &MirrorFacet) -> Result<CoreId, FaultKind> { /* ... */ }
}
```

> **Invariant — projection recoverability:** for every valid `MirrorFacet` there exists a
> replayable relation `RecoverCore(f, trace, replay) = core.id`... must be total over facets
> produced by the same orbit, and property-tested.

**Current:** `Orbit::derive/recover` (`crates/ssk-core/src/lib.rs:13-25`) is pure string
formatting (`format!("facet:{}:{sector:?}", core.id.0.0)`) and a `starts_with("replay:")`
check — deterministic by accident of string construction, not by content-addressing.

**Design: breaking** rewrite. `derive` computes
`FacetId::of(hash_provider, canonical_bytes(&(core.id, seed, phase, sector)))` — deterministic
and reproducible, satisfying recoverability totally, since the relation is a pure function of
`(core, seed, phase, sector)`, all of which the orbit or facet carries. `recover` re-derives
and compares. Depends on the already-real `HashProvider` (`ssk-crypto`) and Section E.1's
content-addressed ids.

### F.3 `birefract()`/`IdentityRay`/`LocatorRay`

PDF (Ch. 4.2, verbatim):

```rust
pub fn birefract(c: &ConnectionIntent, core: &CoreNode, p: &Policy)
    -> Result<(IdentityRay, LocatorRay), FaultKind>;

/// "What the core intends to do."
#[derive(Clone, Serialize, Deserialize)]
pub struct IdentityRay {
    pub core_ref: CoreId,
    pub session_intent: SessionIntent,
    pub key_context: KeyContextRef,
    pub app_policy: PolicyId,
    pub replay_need: ReplayNeed,
    pub residue_policy: ResiduePolicy,
}
/// "How the connection may appear externally."
#[derive(Clone, Serialize, Deserialize)]
pub struct LocatorRay {
    pub allowed_locator_types: LocatorTypeSet,
    pub route_class: RouteClass,
    pub transport_class: TransportClass,
    pub timing_class: TimingClass,
    pub risk_budget: RiskBudget,
    pub cost_budget: CostBudget,
}
```

> **Invariant — plane separation:** for every connection event `e`, `π_id(e) ≠ π_loc(e)` unless
> the runtime is explicitly in direct-IP baseline mode... In Rust the two rays are distinct
> types with no `From`/`Into` conversion between them, so they cannot be accidentally unified.

**Current:** absent entirely. `ssk-stitch::from_intent` (`crates/ssk-stitch/src/lib.rs:5-23`)
goes straight from `ConnectionIntent` to `StitchCandidate`.

**Design:** additive new function in `ssk-core`, plus two new non-interconvertible types (no
`From`/`Into` between them — the plane-separation invariant is enforced at compile time by
this omission). This becomes the real body of `Connection<Canonical>::birefract` (Section E.3).

### F.4 9-variant `LocatorKind`/`LocatorFacet`

PDF (Ch. 4.3, verbatim):

```rust
#[derive(Clone, Serialize, Deserialize)]
pub enum LocatorKind {
    DirectIp, VpnExit, ProxyExit, Relay, Gateway,
    MultiHopPath, LocalOverlay, ControlledEgress, TestHarness,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct LocatorFacet {
    pub id: LocatorId,
    pub kind: LocatorKind,
    pub endpoint: EndpointRef,   // opaque handle, resolved by an adapter
    pub route: RouteClass,
    pub transport: TransportClass,
    pub epoch: EpochId,
    pub ttl: Ttl,
    pub trust: TrustClass,       // Untrusted | Weak | Managed | Owned
    pub cost: CostClass,
    pub risk: RiskClass,
    pub health: HealthStatus,    // Unknown | Live | Degraded | Down
    pub trace: TraceId,
}
```

**Current:** `Locator`/`LocatorType` (`crates/ssk-types/src/lib.rs:79-95`) has 6 of 9 variants
(missing `MultiHopPath, ControlledEgress, TestHarness`) and a 4-field struct (`id,
locator_type, trusted, risk_score`).

**Design: breaking.** Introduce `LocatorFacet` as the canonical type in `ssk-types`; migrate
every consumer (`ssk-locator`, `ssk-gates`, `ssk-bcik`, `ssk-stitch`, `ssk-runtime` fixtures).
This is one of the larger churn items — budget it explicitly in Phase 1 (Section V).

---

## G. Locator & Funnel-DAG

**PDF ref: Ch. 6.** Lands in `ssk-locator`.

### G.1 `LocatorAdapter`/`LocatorPool` trait + real `claims_external_plurality()`

PDF (Ch. 6.2, verbatim):

```rust
pub trait LocatorAdapter: Send + Sync {
    fn kind(&self) -> LocatorKind;
    /// Resolve an opaque endpoint handle for use; no CoreId is passed in.
    fn resolve(&self, req: &EgressRequest) -> Result<EndpointRef, FaultKind>;
    fn probe(&self, ep: &EndpointRef) -> HealthStatus;
    fn release(&self, ep: EndpointRef);
}
pub trait LocatorPool: Send + Sync {
    fn claims_external_plurality(&self) -> bool;
    fn candidates(&self, ray: &LocatorRay, epoch: EpochId) -> Vec<LocatorFacet>;
    fn health(&self, id: LocatorId) -> HealthStatus;
    fn account(&mut self, id: LocatorId, use_record: LocatorUse);
}
```

> **Axiom — locator reality condition:** `LocatorPool::claims_external_plurality()` returns
> `true` only if the pool contains at least two distinct, live locator facets whose observable
> surfaces differ. A pool with a single `DirectIp` facet returns `false` and the runtime
> records a high-linkability baseline. This axiom is enforced at policy-load time and
> re-checked per epoch.

**Current:** `LocatorPool` (`crates/ssk-locator/src/lib.rs:6-29`) is a concrete struct with
`get`/`select_first_viable`; no adapter abstraction, no plurality claim of any kind.

**Design: breaking** rename — the existing concrete struct becomes `StaticLocatorPool`, a
default in-process implementation of the new trait. `ssk-runtime::Runtime<'a, L>` becomes
generic over `impl LocatorPool` rather than the concrete struct.
`claims_external_plurality()` must be a **real** count of distinct live facets with differing
`endpoint` — not a hardcoded constant — this is the literal honesty check the audit
(Section A) flags: it must return `false` for a single-`LocalOverlay`-pool MVR configuration,
never a fabricated `true`.

### G.2 `StitchEdge`/`LocatorGraph`/`HyperEdge`/`select_path`

PDF (Ch. 6.3-6.4, verbatim):

```rust
#[derive(Clone, Serialize, Deserialize)]
pub struct StitchEdge {
    pub id: EdgeId,
    pub src: LocatorId,
    pub dst: LocatorId,
    pub map: EdgeTransform,          // Routing | Framing | TransportAdapt | RelayHandoff
    pub lifetime: Ttl,
    pub policy_reason: PolicyReason,
    pub capability: Option<CapabilityId>,
    pub boundary: BoundaryRef,
    pub trace: TraceId,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct LocatorGraph {
    pub nodes: Vec<LocatorFacet>,
    pub edges: Vec<StitchEdge>,       // ordinary transitions
    pub hyperedges: Vec<HyperEdge>,   // multi-dependency transitions
}
pub fn select_path(theta: &PhaseVector, g: &LocatorGraph,
    cube: &Hypercube, p: &Policy) -> Result<LocatorPath, FaultKind>;
```

> **Invariant — edge explicitness:** every `StitchEdge` has an id, lifetime, policy reason,
> typed transform, boundary behavior and trace. An edge missing any of these fields fails
> deserialization validation and cannot enter the graph. `EdgeTransform` is a closed enum;
> there is no opaque tunnel variant.

**Current — Phase 6 done, with two disclosed elaborations:** `crates/ssk-types/src/lib.rs` now
has real `EdgeId`/`EdgeTransform`/`PolicyReason`/`StitchEdge`/`HyperEdge`/`LocatorGraph`/
`LocatorPath`; `crates/ssk-locator/src/lib.rs` has a real, tested `select_path` — a
breadth-first search over both `StitchEdge`s and `HyperEdge`s (a hyperedge only unlocks once
every one of its `requires` locators has already been reached), skipping any edge whose
`lifetime.0 == 0` (the same "non-zero TTL" convention `DissolutionGate`/`TimingCell` already
use elsewhere).

Two disclosed elaborations, both necessary rather than optional:
1. **No `Hypercube` parameter.** `ssk-locator` cannot depend on `ssk-gates::pch::Hypercube`
   directly — `ssk-gates` already depends on `ssk-locator` transitively (via `ssk-bcik`), so
   the reverse edge would cycle, the same constraint discovered in Phases 3-5. Even ignoring
   the cycle, `Hypercube::check` needs a full `StitchCandidate`, which does not exist yet at
   path-selection time (ch. 14.1's spine places `LocatorPath` *before* the second `PCH
   Projection` stage). `select_path` is instead generic over a new, locally-defined
   `PathProjectionCheck` trait; `ssk-gates` (or a caller above it) may implement it once a
   facet-level PCH pre-check makes sense. No implementation is wired in yet — this codebase's
   own call sites (tests) only ever pass the trivial `AlwaysPass`.
2. **An explicit `start: &LocatorId` parameter.** The PDF's excerpted 4-parameter signature
   names no origin or destination; a shortest-path search needs one. `select_path` returns the
   nearest reachable locator that passes the injected check, which is the natural reading of
   "select a path" absent a named target.

Real egress adapters and health probing behind the pre-existing (already-scaffolded, unused)
`async-edge` Cargo feature remain **out of scope** for this phase — the doc's own Section X
already commits real network I/O exclusively to the Desktop track's `ssk-netcore`.

Tested: `a_locator_already_passing_is_a_zero_hop_path`,
`select_path_finds_the_shortest_edge_chain`, `expired_edges_are_never_traversed`,
`a_hyperedge_unlocks_only_once_every_requirement_is_reached`, `unknown_start_locator_is_unavailable`.

---

## H. Hypertoroidal Scheduler

**PDF ref: Ch. 7.** Lands in `ssk-scheduler`.

PDF (Ch. 7.2, verbatim):

```rust
pub enum SchedulerMode {
    /// Pure: phase advances by a fixed FrequencyVector. Fully reproducible.
    Deterministic,
    /// Seeded: a recorded seed drives a deterministic PRNG that jitters increments;
    /// the seed is stored in the RunDescriptor so replay is exact.
    Seeded(SchedulerSeed),
}
pub struct HypertoroidalScheduler {
    theta: PhaseVector, freq: FrequencyVector, mode: SchedulerMode, epoch: EpochId,
}
impl HypertoroidalScheduler {
    pub fn tick(&mut self) -> Tick { /* advance each axis mod PHASE_MODULUS */ }
    pub fn phase(&self) -> &PhaseVector { &self.theta }
    /// Visibility predicate: R_eps(x, theta) = 1{ d_T(theta, psi(x)) < eps_x }.
    pub fn visible(&self, target: &PhaseVector, w: Window) -> bool { /* toroidal dist */ }
}
```

> **Definition — toroidal distance:** for phases `a, b` on one axis, `d(a,b) = min(|a-b|,
> M-|a-b|)` with `M = PHASE_MODULUS`. The vector distance `d_T` is the max (or configured `Lp`)
> over axes. `visible` is a necessary precondition for candidate formation, never a sufficient
> condition for materialization.

**Current:** `DeterministicScheduler` (`crates/ssk-scheduler/src/lib.rs:6-42`) implements the
fixed-point toroidal phase math faithfully (`Phase((theta + freq) % PHASE_MODULUS)` per axis),
but `seeded: bool` is stored in `SchedulerState` and never read in `tick()`; there is no
`SchedulerMode`, no `SchedulerSeed`, and no `visible()`.

**Design: breaking rename** `DeterministicScheduler` → `HypertoroidalScheduler`. `Seeded` mode
needs an actual deterministic PRNG jitter — add `rand_pcg` (small, pure-Rust,
`#![forbid(unsafe_code)]`-compatible) as a new optional dependency, since the workspace already
depends on `rand` for key generation. `visible()` implements the literal toroidal-distance
formula above. This item nominally over-satisfies SSKΩ-1 (already claimed done) but must be
finished to the letter before Section I's PCH work, since `visible()` is PCH's stated necessary
precondition (Ch. 7.2's own cross-reference to Ch. 8).

---

## I. Projective Connection Hypercube + Gabriel Constraint Cells

**PDF ref: Ch. 8, Ch. 10.**

### I.1 PCH

PDF (Ch. 8.1-8.2, verbatim):

```rust
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Axis {
    Identity, Locator, Protocol, Timing, Trust, Risk, Capability, Replay, Boundary,
}
/// The projection of a candidate onto one axis.
pub enum Projection {
    Ok(AxisWeight),
    Undefined,
    Inconsistent(Reason),
    OverBudget(Reason),  // -> Hold
    ReplayGap(Reason),
}
pub struct ConnectionCell {
    pub addr: CellAddr,
    pub weight: CellWeight, // (mass, coherence, phase_ready, risk, residue, trace, gate)
    pub constraints: Vec<Constraint>,
    pub gate: GateStatus,
    pub boundary: BoundaryRef,
    pub trace: TraceId,
    pub residue: ResidueRef,
}
pub trait AxisProjector { fn project(&self, sc: &StitchCandidate) -> Projection; }
pub struct Hypercube { projectors: [Box<dyn AxisProjector>; 9] }
impl Hypercube {
    pub fn check(&self, sc: &StitchCandidate) -> PchOutcome {
        for (axis, p) in self.projectors.iter().enumerate() {
            match p.project(sc) {
                Projection::Ok(_) => continue,
                Projection::Undefined => return PchOutcome::fail(axis, "undefined"),
                Projection::Inconsistent(r) => return PchOutcome::fail(axis, r),
                Projection::ReplayGap(r) => return PchOutcome::fail(axis, r),
                Projection::OverBudget(r) => return PchOutcome::hold(axis, r),
            }
        }
        PchOutcome::Pass
    }
}
```

> **Invariant — projection consistency:** `∃a ∈ Axes : Invalid(π_a(sc)) ⇒ PassPCH(sc) = 0`. A
> candidate may not pass PCH if any required axis projection is undefined, contradictory, over
> budget, or non-replayable. `OverBudget` yields `Hold` (diagnosable, non-persistent); all
> other failures yield `Fail` with a typed residue.

### I.2 Gabriel Constraint Cells

PDF (Ch. 10, verbatim):

```rust
pub enum CellRole {
    Identity, Locator, Protocol, Timing, Risk, Capability, Boundary, Replay, Focus,
}
pub enum CellVerdict { Propose, Hold(Reason), Refine(Hint), Reject(Reason), Quarantine(Reason) }
pub trait ConstraintCell: Send + Sync {
    fn role(&self) -> CellRole;
    /// Local, side-effect-free evaluation over a bounded local view.
    fn evaluate(&self, cand: &StitchCandidate, view: &LocalView, p: &Policy) -> CellVerdict;
}
/// The Gabriel film: all active cells at a phase state.
pub struct GabrielFilm { cells: Vec<Box<dyn ConstraintCell>> }
impl GabrielFilm {
    pub fn evaluate_all(&self, cand: &StitchCandidate, p: &Policy) -> Vec<CellVerdict>;
}
```

> **Contract — cellular non-persistence:** a `ConstraintCell` receives only a bounded
> `LocalView` and returns a `CellVerdict`. It has no reference to `&mut StitchTensor` and no
> interior mutability over shared runtime state — enforced by the trait signature: `evaluate`
> takes `&self` and shared references only. Cells are **not authorities**: "only the global
> gate vector can authorize a tensor mutation."

**Current:** neither object exists anywhere in the tree [4].

**Design: crate-placement decision (PDF is silent on this).** The PDF's repository blueprint
(Ch. 20) does not list a dedicated PCH/Gabriel crate — `HypercubeGate` is one of the twelve
gates that already lives in `ssk-gates`. Land `Axis`/`Projection`/`ConnectionCell`/
`AxisProjector`/`Hypercube` and `CellRole`/`CellVerdict`/`ConstraintCell`/`GabrielFilm` as new
modules **inside `ssk-gates`** (`ssk-gates::pch`, `ssk-gates::gabriel`) — a deliberate,
disclosed deviation from the letter of the repo blueprint, justified by co-locating with their
sole consumer rather than inventing a new crate the PDF never asked for. **Additive** — no
existing type is touched, only new modules.

---

## J. BCIK Crossing Kernel

**PDF ref: Ch. 9.** Lands in `ssk-bcik` (kernel), `ssk-types` (`BcikStitch`, residues).

PDF (Ch. 9.1-9.2, verbatim):

```rust
pub struct Bcik<'p> {
    null_ref: NullRef,             // Z: external null reference (not a network state)
    boundary: BoundaryOperator,    // partial-d
    seam: SeamInterface,           // Sigma
    residue: ResidueRegister,      // R_res
    provider: &'p dyn HashProvider,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct BcikStitch {
    pub id: StitchId,
    pub facet: FacetId,
    pub locator: LocatorId,
    pub fiber: FiberType,
    pub phase: PhaseVector,
    pub capability: Option<CapabilityId>,
    pub seam: SeamWitness,
    pub boundary: BoundaryRecord,
    pub residues: Vec<ResidueId>,
    pub gate_report: Option<GateReportId>,
    pub trace: TraceId,
    pub replay: ReplayRef,
}
impl<'p> Bcik<'p> {
    /// Cross the seam. Either returns a closed stitch OR a boundary residue;
    /// never a silent success and never a silent drop.
    pub fn cross(&mut self, facet: &MirrorFacet, loc: &LocatorFacet,
        fiber: FiberType, p: &Policy) -> CrossOutcome;
}
pub enum CrossOutcome {
    Closed(BcikStitch),
    Residue(BoundaryResidue),  // typed, visible, recorded
}
```

> **Invariant — no silent crossing:** no identity/locator crossing is valid without a BCIK
> witness. In Rust, `cross` returns `CrossOutcome`, which **has no unit success variant**: the
> caller is forced to handle either a closed stitch or a residue.

PDF (Ch. 9.2, residue taxonomy — verbatim, this exactly matches the codebase's existing
`ResidueKind` enum with two additional named-in-comment variants already present, confirmed):

```rust
#[derive(Clone, Serialize, Deserialize)]
pub enum ResidueKind {
    Identity, Locator, Timing, Protocol, Capability, Replay, Correlation, Focus, Boundary,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct BoundaryResidue {
    pub id: ResidueId,
    pub kind: ResidueKind,
    pub severity: Severity,
    pub origin: TraceId,
    pub detail: ResidueDetail,
    pub open_obligation: bool,  // must policy quarantine/hold until resolved?
}
pub struct ResidueRegister { entries: Vec<BoundaryResidue> }
impl ResidueRegister {
    pub fn emit(&mut self, r: BoundaryResidue) -> ResidueId { /* append + hash-chain */ }
    pub fn open_obligations(&self) -> impl Iterator<Item = &BoundaryResidue> { /* ... */ }
}
```

**Current:** `cross()` (`crates/ssk-bcik/src/lib.rs:12-22`) returns `CrossOutcome::Closed`
(unit-like, no payload) when `candidate.seam_ok && candidate.boundary_complete` — both booleans
hardcoded `true` at `crates/ssk-stitch/src/lib.rs:17-19`. `BoundaryResidue`
(`crates/ssk-types/src/lib.rs:174-180`) has only `id, kind, source_gate, detail` — missing
`severity, origin, open_obligation`. No `ResidueRegister` exists; residues are collected into
plain `Vec`s.

**Design: breaking.** New `Bcik<'p>{null_ref, boundary, seam, residue, provider}` struct
replaces the free function; `CrossOutcome::Closed(BcikStitch)` now carries a real payload.
**Depends on Section F** (real `MirrorFacet`/`LocatorFacet`) landing first — `BcikStitch`
references both by their real ids. `BoundaryResidue` gains `severity`, `origin`,
`open_obligation` (breaking field addition — contain the churn via a `BoundaryResidue::new(...)`
builder so every call site changes once, not per-field). `ResidueRegister{entries}` with
`emit()`/`open_obligations()` replaces ad-hoc `Vec<BoundaryResidue>` construction scattered
through `ssk-gates`/`ssk-bcik`/`ssk-faultscan`.

---

## K. Gate System

**PDF ref: Ch. 11.** Lands in `ssk-gates`.

PDF (Ch. 11.1-11.2, verbatim):

```rust
pub struct GateWitness { pub gate: GateId, pub evidence: EvidenceRef }
pub enum GateVerdict {
    Pass(GateWitness), Hold(ResidueId), Refine(ResidueId), Reject(ResidueId), Quarantine(ResidueId),
}
/// Every gate: input type, output witness, failure mode, residue, audit, replay.
pub trait Gate: Send + Sync {
    fn id(&self) -> GateId;
    fn required(&self) -> bool;               // mandatory gates cannot be skipped
    fn residue_on_fail(&self) -> ResidueKind; // typed residue emitted on failure
    fn evaluate(&self, sc: &StitchCandidate, ctx: &GateCtx) -> GateVerdict;
}
```

The twelve gates and their real checks (Ch. 11.2 table, verbatim):

| Gate | Checks | Residue on fail |
|------|--------|------------------|
| `CoreGate` | canonicalization, core signature, policy root | Identity |
| `MirrorGate` | facet in core orbit, sector valid, recoverable | Identity |
| `LocatorGate` | locator exists, type permitted, trust/cost/risk bounds | Locator |
| `BcikGate` | seam, boundary, residual projector, no silent crossing | Boundary |
| `HypercubeGate` | all PCH projections defined and compatible | Boundary |
| `CapabilityGate` | witness valid, scoped, unexpired, replayable | Capability |
| `FiberGate` | fiber typed, transform invariants preserved | Protocol |
| `PrivacyGate` | linkability within budget; metadata budget respected | Correlation |
| `BoundaryGate` | residue register consistent; no missing residue field | Boundary |
| `FocusGate` | responses can refocus to canonical core class | Focus |
| `ReplayGate` | deterministic replay under run descriptor | Replay |
| `DissolutionGate` | TTL/epoch fields present and finalizable | Timing |

PDF (Ch. 11.2, `GateVector::evaluate` — verbatim; **note there is no `break` anywhere in this
loop**):

```rust
pub struct GateVector { gates: Vec<Box<dyn Gate>> } // ordered
impl GateVector {
    pub fn evaluate(&self, sc: &StitchCandidate, ctx: &GateCtx) -> GateReport {
        let mut witnesses = Vec::new();
        let (mut refine, mut quarantine, mut reject) = (None, None, None);
        for g in &self.gates {
            match g.evaluate(sc, ctx) {
                GateVerdict::Pass(w) => witnesses.push(w),
                GateVerdict::Hold(r) | GateVerdict::Refine(r) => refine.get_or_insert(r),
                GateVerdict::Quarantine(r) => { quarantine.get_or_insert(r); },
                GateVerdict::Reject(r) => { reject.get_or_insert(r); },
            };
        }
        GateReport::resolve(witnesses, quarantine, refine, reject)
    }
}
```

> "Evaluation is ordered (cheap, structural gates first). On the first Quarantine the vector
> returns Quarantine; else on the first Refine, Refine; else on any failure, Reject; only an
> all-pass yields Pass." — the **resolution priority** is first-found-wins by category, but
> **every gate is still evaluated**; the priority is applied only after the full loop.

**Current:** single `BasicGate` (`crates/ssk-gates/src/lib.rs:22-120`) dispatching all 12
`GateId` variants in one `match`; 11 of 12 checks are single-boolean-flag reads off
`StitchCandidate`; only `PrivacyGate` (lines 94-102) computes a derived value via
`ssk_privacy::linkability_score`. `GateVector::evaluate` (lines 138-176) has an explicit
`break` on `Quarantine`/`Reject` (lines 148, 153) — **this contradicts the PDF's own
pseudocode**, which has no break in its loop.

**Design: breaking rewrite.** Introduce twelve real gate structs (`CoreGate`, `MirrorGate`,
`LocatorGate`, `BcikGate`, `HypercubeGate`, `CapabilityGate`, `FiberGate`, `PrivacyGate`,
`BoundaryGate`, `FocusGate`, `ReplayGate`, `DissolutionGate`), each implementing the real
"Checks" column above (e.g. `HypercubeGate` calls into Section I's `Hypercube::check`;
`CapabilityGate` validates a real `CapabilityWitness`'s scope/epoch/expiry, not a bool). Fix
`GateVector::evaluate` to drop the early `break`s — **this is a small, isolated, high-value
correctness fix independently landable ahead of the rest of Section K** (it needs no new
types, just deleting two `break` statements and re-verifying the existing gate tests still
pass). `GateProfile` (`crates/ssk-config/src/lib.rs:30-46`, currently `order`+`fail_closed`
only) gains `thresholds`, `required_evidence`, `failure_policy` (must be `NoMaterialization`),
`hold_policy`, `pass_policy` per Ch. 11.3 — lands alongside Section S's schema work.

---

## L. Cryptographic & Capability Layer

**PDF ref: Ch. 5.** Lands in `ssk-crypto` (providers), `ssk-types` (`CapabilityWitness`).

PDF (Ch. 5.1-5.2, verbatim):

```rust
pub trait CapabilityWitnessProvider: Send + Sync {
    fn issue(&self, claim: &CapabilityClaim, subject: &SubjectClass) -> Result<CapabilityWitness, CryptoError>;
    fn verify(&self, w: &CapabilityWitness, ctx: &VerifyCtx) -> Result<CapabilityVerdict, CryptoError>;
    fn kind(&self) -> WitnessKind; // Signature | Token | ZkStyle | PolicyCert
}
#[derive(Clone, Serialize, Deserialize)]
pub struct CapabilityWitness {
    pub id: CapabilityId,
    pub claim: CapabilityClaim,    // e.g. "may use locator class Relay in epoch E"
    pub scope: Scope,              // action + facet-class binding
    pub issuer: IssuerRef,
    pub subject_class: SubjectClass,
    pub epoch: EpochId,
    pub expiry: Ttl,
    pub proof: ProofBytes,         // opaque; validated by the provider
    pub trace: TraceId,
}
```

> **Axiom — proof scope:** a capability witness proves only its declared claim. It does not
> prove payload truth, locator safety, absence of correlation, or validity outside its
> scope/epoch. **Privacy property:** "the intended privacy gain is that admission is decided
> by scoped capability rather than by revealing the core identity... the runtime only requires
> that the witness verification does not require disclosing `CoreId` to the locator side."

**Current:** `crates/ssk-types/src/lib.rs:114` — `capability_witness: bool`.
`CapabilityWitnessProvider`/`KeyAgreementProvider` (`crates/ssk-crypto/src/lib.rs:15-27`) are
trait-only, zero implementations. `SignatureProvider`/`AeadProvider` are real
(`Ed25519KeyPair`, `ChaCha20Poly1305Provider`, `crates/ssk-crypto/src/lib.rs:35-176`, from a
prior implementation pass).

**Design: breaking.** `StitchCandidate.capability_witness: bool` → `capability:
Option<CapabilityWitness>`. Concrete implementation: `CapabilityWitnessProvider`'s
`WitnessKind::Signature` built directly on the already-real `Ed25519KeyPair` — issue signs the
canonical claim bytes, verify checks the signature plus scope/epoch/expiry locally. **This
needs no new crypto library**, only new `ssk-crypto` code wrapping existing primitives.
`KeyAgreementProvider` (x25519) is implementable with **zero new Cargo dependencies**:
`x25519-dalek` is already declared as an unused optional dependency in
`crates/ssk-crypto/Cargo.toml` behind the `crypto` feature. `WitnessKind::ZkStyle`/`Token`/
`PolicyCert` are explicitly deferred (Section X) — implementing a ZK-style witness casually
would itself risk violating the PDF's own "no self-designed cryptography" non-goal (Ch. 1.3,
Ch. 5 heading: "SSK Ω contains no self-designed cryptography").

---

## M. Persistent Stitch Tensor

**PDF ref: Ch. 12.** Lands in `ssk-tensor`.

PDF (Ch. 12.1-12.2, verbatim):

```rust
#[derive(Clone, Serialize, Deserialize)]
pub struct StitchTensorEntry {
    pub id: StitchId,
    pub stitch: BcikStitch,
    pub gate_report: GateReportId,
    pub accepted_at: Tick,
    pub epoch: EpochId,
    pub ttl: Ttl,
    pub prev_hash: Digest,
    pub entry_hash: Digest, // = H(prev_hash || canonical(self without entry_hash))
}
pub struct StitchTensor {
    graph: StitchGraph,               // G_s: accepted stitch graph
    entries: Vec<StitchTensorEntry>,
    head: Digest,                     // current chain head
    backend: Box<dyn StorageBackend>,
}
impl StitchTensor {
    /// Only reachable with gate-passed candidates (typestate, Ch. 3).
    pub fn apply_sorted(&mut self, accepted: Vec<Accepted>) -> Result<Vec<StitchId>, FaultKind> {
        // deterministic ordering by (epoch, StitchId) for replay stability
        let mut acc = accepted; acc.sort_by_key(|a| (a.epoch, a.stitch.id));
        let mut ids = Vec::new();
        for a in acc {
            let entry = self.chain(a)?; // computes prev/entry hash
            self.backend.append(&entry)?;
            self.graph.insert(&entry.stitch);
            self.head = entry.entry_hash;
            ids.push(entry.id);
        }
        Ok(ids)
    }
}
pub trait StorageBackend: Send + Sync {
    fn append(&mut self, e: &StitchTensorEntry) -> Result<(), FaultKind>;
    fn get(&self, id: StitchId) -> Option<StitchTensorEntry>;
    fn iter(&self) -> Box<dyn Iterator<Item = StitchTensorEntry> + '_>;
    fn head(&self) -> Digest;
}
```

> **Theorem — gate failure preserves the tensor:** if no candidate passes the gate vector at
> tick `t`, then `ST(t+1) = ST(t)`. "In the API this is guaranteed because acceptance requires
> a `Connection<GatePassed>` value, which cannot exist for a failed candidate."
> **Theorem — no persistent stitch without replay:** every tensor revision implies replay
> readiness; the `ReplayGate` is mandatory and part of the gate vector.

**Current — Phase 4 done (in `ssk-tensor`):** `crates/ssk-tensor/src/lib.rs` now has a real
`StitchTensor{graph, head, backend: Box<dyn StorageBackend>}`; `StorageBackend` is a supertrait
of the already-real `GenericLedgerBackend<StitchTensorEntry>` adding `get`/`iter`/`head`
(blanket-implemented for every existing backend type, mirroring `LedgerBackend`'s own pattern);
`StitchGraph` is a real content-addressed index with `insert`/`contains`/`len`; `Accepted`
(this document's own disclosed elaboration — the PDF names the type but the excerpted text does
not enumerate its fields) carries exactly what `apply_sorted` needs to build a
`StitchTensorEntry` and sort deterministically. `apply_sorted` batch-sorts by
`(epoch, StitchId)` before chaining, tested including the empty-input case
(`empty_apply_sorted_preserves_the_tensor`) and a from-disk graph/head rebuild
(`open_rebuilds_graph_and_head_from_existing_entries`). Two disclosed, documented deviations
from the PDF's literal `StorageBackend` signature (both already inherited from
`GenericLedgerBackend`'s own established pattern): `append` takes `&self` not `&mut self` and
returns `TensorError` not `FaultKind`; `get`/`iter` degrade to `None`/empty on a storage read
failure rather than panicking.

**Not yet done:** wiring `StitchTensor` into `ssk-runtime`'s live pipeline (still writes the
older flat `TensorEntry` via `make_entry`) and into `Connection<GatePassed>::materialize`
(Section E.3, still a stub) — both deferred to Phase 5 alongside the `RunOutcome`/pipeline-stage
rework (Section R). Wiring `materialize` today would need the gate vector to hand back the real
`BcikStitch` it already computes inside `BcikGate::evaluate` — currently discarded after the
gate resolves to `Pass` — rather than recomputing it a second time; that plumbing change is
Section R's job, done once for both `RunOutcome`'s redesign and this wiring together.

---

## N. Concave Reanalysis Focus

**PDF ref: Ch. 13.** Lands in `ssk-focus`.

PDF (Ch. 13.1, verbatim):

```rust
#[derive(Clone, Serialize, Deserialize)]
pub struct Response {
    pub facet: FacetId, pub locator: LocatorId, pub fiber: FiberType,
    pub trace: TraceId, pub payload_digest: Digest, // payload itself is not stored
}
#[derive(Clone, Serialize, Deserialize)]
pub struct FocusReport {
    pub reconstructed: CoreSessionClass,
    pub residues: Vec<ResidueId>,
    pub replay: ReplayReportRef,
    pub linkability: LinkabilityReport,
    pub verdict: FocusVerdict, // Pass | ClassMismatch | Ambiguous
}
pub struct FocusEngine<'p> { provider: &'p dyn HashProvider }
impl<'p> FocusEngine<'p> {
    pub fn reanalyze(&self, responses: &[Response], core: &CoreNode, p: &Policy) -> FocusReport;
}
```

> **Invariant — focus does not create truth:** "Focus reconstructs an internal session class
> from response evidence. It does not prove payload truth, endpoint trustworthiness, or
> absence of observation. This is a documented, tested limit, not a hidden assumption."

**Current — Phase 5 done:** `crates/ssk-focus/src/lib.rs` now has real `Response`/
`CoreSessionClass`/`FocusVerdict`/`FocusReport` and a real `FocusEngine::reanalyze`.
Reconstruction is genuinely bounded, not guessed: a session reconstructs to
`CoreSessionClass::Reconstructed(core.id)` only when every `Response` shares one `FacetId` and
the core is canonically signed; an empty response set is `Ambiguous`; more than one distinct
facet (no facet-to-core directory exists in this codebase to resolve that honestly) is
`ClassMismatch`. `linkability` is computed for real via the new `HeuristicLinkabilityEstimator`
(Section O) over a locator-reuse-derived `ObservedSurface` (reused locators raise risk — the
only correlation signal a bare `Response` carries). `replay: ReplayReportRef` is a real digest
of the session's response hashes via the `HashProvider` the engine holds, standing in for a
replay-report registry that does not exist yet. The original `refocuses()` boolean is kept
**unchanged** — it remains `FocusGate`'s real backing check (Section K), a different, faster,
gate-time concern than this heavier session reconstruction.

Tested: `empty_responses_are_ambiguous`, `single_facet_responses_reconstruct_cleanly` (also
proves non-zero linkability risk from a reused locator), `mixed_facet_responses_are_a_class_mismatch`.

---

## O. Privacy & Linkability Model

**PDF ref: Ch. 15.** Lands in `ssk-privacy`.

PDF (Ch. 15.2-15.3, verbatim). The PDF's own honest-capability matrix (paraphrased table,
Ch. 15.2) states the runtime's posture against each adversary class, ending with:

> **Axiom — no absolute anonymity claim:** "No conformance class may claim perfect anonymity
> or global untraceability... Global passive observer: Out of scope. The runtime explicitly
> does not claim resistance to a global passive adversary."

```rust
pub trait LinkabilityEstimator: Send + Sync {
    /// Returns a bounded risk score in [0,1] under the declared adversary model.
    fn estimate(&self, obs: &ObservedSurface, ctx: &ThreatCtx) -> LinkRisk;
    fn adversary_model(&self) -> AdversaryModel; // recorded in the report
}
#[derive(Clone, Serialize, Deserialize)]
pub struct LinkabilityReport {
    pub score: LinkRisk,
    pub adversary_model: AdversaryModel,
    pub high_risk_components: Vec<SurfaceComponent>, // each must have a residue entry
}
```

**Current — Phase 5 done:** `crates/ssk-privacy/src/lib.rs` now has the real
`LinkabilityEstimator` trait, `AdversaryModel{PartialNetworkObserver, GlobalPassiveObserver}`,
`LinkRisk`, `SurfaceComponent`, `ObservedSurface`, `ThreatCtx` (a Phase-placeholder context
parameter, same disclosed pattern as `ssk-gates::GateCtx`), and `LinkabilityReport`. The
original `linkability_score()` heuristic is kept **unchanged** for `PrivacyGate`'s existing
call site (Section K); the new `HeuristicLinkabilityEstimator` wraps the same spirit of
heuristic behind the real trait, declaring `AdversaryModel::PartialNetworkObserver` — the
honest posture a bounded, budget-checked estimate implies, not an anonymity claim. `report()`
has a default trait-method body flagging any component with `risk_score > 70` into
`high_risk_components`.

Tested: `heuristic_estimator_declares_partial_network_observer`,
`report_flags_high_risk_components`, `report_omits_low_risk_components`.

---

## P. Faultscan

**PDF ref: Ch. 17.** Lands in `ssk-faultscan` (rename) and `ssk-types` (real vocabulary).

PDF (Ch. 17.1, verbatim, the full 18-variant taxonomy):

```rust
#[derive(Clone, Serialize, Deserialize)]
pub enum FaultKind {
    CoreNotCanonical, FacetNotRecoverable, LocatorUnavailable, SingleIpOverclaim,
    BcikSeamMissing, PchProjectionGap, CapabilityInvalid, PrivacyBudgetExceeded,
    TimingResidueHigh, FiberInvariantFailure, FocusAmbiguity, ReplayGap,
    ReanalysisMismatch, SilentResidueAttempt, DissolutionFailure, StorageFailure,
    ConfigInvalid, CryptoProviderError,
}
#[derive(Clone, Copy, Serialize, Deserialize)]
pub enum Severity { Info, Low, High, Critical }
pub struct FaultEvent {
    pub kind: FaultKind, pub severity: Severity,
    pub detection: DetectionSource, pub residue: Option<ResidueId>, pub trace: TraceId,
}
pub trait Faultscan {
    fn scan(&self, ctx: &RuntimeState) -> Vec<FaultEvent>;
    fn fail_closed(&self, faults: &[FaultEvent]) -> bool {
        faults.iter().any(|f| matches!(f.severity, Severity::Critical))
    }
}
```

> **Axiom — metrics do not replace gates:** a metric can inform a gate, but no aggregate score
> overrides a required gate.

**Current:** `crates/ssk-faultscan/src/lib.rs:16-29` — a real, working **chaos-injection
harness**: `FaultKind{SignatureCorruption, CapabilityWithdrawal, TtlExpiry, ReplayDrift,
AttestationFailure, LocatorUntrust}` (6 variants), API is `inject_fault`/`run_drill`/
`run_playbook` — structurally unrelated to the PDF's 18-variant **detection** taxonomy. These
are two genuinely different concerns wearing the same name.

**Design:** **rename** the existing enum to `ChaosFaultKind` in `ssk-faultscan` — a small,
contained, mechanical rename touching only this crate's tests and the `ssk-cli` `chaos drill`
call site. This frees up `FaultKind` for the spec's 18-variant foundation vocabulary (Section
E.5), which lands in `ssk-types`. Add the `Faultscan` trait + `FaultEvent`/`Severity` to
`ssk-faultscan`, with a first real `scan()` implementation that derives `FaultEvent`s from
existing runtime signals (gate residues, replay divergence, storage errors) rather than
inventing a new detection subsystem from scratch.

---

## Q. Replay Engine

**PDF ref: Ch. 16.3.** Lands in `ssk-replay` (trait impl), `ssk-core` (shared pipeline
extraction).

PDF (Ch. 16.3, verbatim):

```rust
pub trait ReplayEngine {
    /// Re-executes the decision core under a manifest and diffs every step.
    fn replay(&self, m: &ReplayManifest, state: &RuntimeState) -> ReplayVerdict;
}
pub enum ReplayVerdict {
    Deterministic,                                      // bit-identical trace + outcome
    Divergent { first_diff: PipelineStep, detail: DiffDetail }, // -> Replay residue
}
```

> **Replay determinism obligation:** given identical `RunDescriptor`, identical prior tensor
> head, and identical input digest, the decision core must reproduce identical candidates,
> gate reports, tensor updates and focus reports. All nondeterminism sources (time, randomness,
> map iteration order, float arithmetic) are excluded from the decision core by construction.

**Current — Phase 5 done, with a disclosed placement correction:** the pure decision-core
pipeline (scheduler tick → orbit derive → locator select → stitch candidate → gate evaluate →
trace chain) is now extracted into `pub fn execute_pipeline(...) -> Result<PipelineExecution, RuntimeError>`
in `crates/ssk-runtime/src/lib.rs` — **not** `ssk-core` as originally suggested. `ssk-core`
cannot host it: the pipeline genuinely needs `ssk-identity` and `ssk-stitch`, and both of those
crates already depend on `ssk-core` (for `MirrorOrbit`/`CoreObject`), so `ssk-core` adding a
dependency on either would cycle — the same class of constraint discovered during Phase 3/4.
`Runtime::run_once_with_context` now calls `execute_pipeline` and only adds tensor mutation on
top. `ssk-replay` gained a normal dependency on `ssk-runtime` to call the same function; the
reverse edge (`ssk-runtime` → `ssk-replay`, previously used only by one integration test) was
moved to `[dev-dependencies]` in `ssk-runtime`'s `Cargo.toml` — Cargo permits a dev-dependency
back-edge with no cycle error, since dev-dependencies aren't part of the graph a downstream
crate depends on. `ReplayEngine::replay`'s signature changed to take the original
`intent`/`pool`/`determinism`/`gate_vector` (a manifest is a compact commitment, not an archive
of the original request — the PDF's `RuntimeState` parameter isn't detailed in the excerpted
text, so this is this document's own disclosed elaboration of it) and now genuinely
re-executes, diffing the fresh `trace_head`/gate-report digest against the manifest's stored
values — no longer just comparing two outcomes the caller computed externally.

Tested: `genuinely_re_executed_run_matches_its_own_manifest`,
`a_mismatched_manifest_is_reported_as_divergent` (in `ssk-replay`); the pre-existing
`deterministic_replay_vector_matches` (`ssk-runtime`'s own integration test) and `ssk-cli`'s
`replay-verify` command updated to the new call shape.

---

## R. Runtime Pipeline & RunOutcome

**PDF ref: Ch. 14.** Lands in `ssk-runtime` (pipeline), `ssk-types` (`RunOutcome`).

PDF (Ch. 14.1, verbatim, the full 20-stage spine):

> `ConnectionIntent → Canonicalization → CoreSignature → BirefringentSplit → (IdentityRay,
> LocatorRay) → MirrorOrbit → PCH Placement → HypertoroidalPhase → GabrielEvaluation → BCIK
> Crossing → CapabilityCheck → LocatorPath → PCH Projection → GateVector →
> TensorMaterialization → FiberExecution → ResponseCapture → ConcaveFocus →
> LinkabilityResidue → ReplayVerify → CommitOrDissolve.`

PDF (Ch. 14.2, verbatim):

```rust
pub enum RunOutcome {
    Pass { stitches: Vec<StitchId>, focus: FocusReport, replay: ReplayReportRef },
    HoldRefine { residues: Vec<ResidueId> },
    DissolveRejectQuarantine { residues: Vec<ResidueId>, audit: AuditRef },
}
pub fn run_once(intent: ConnectionIntent, state: &mut RuntimeState,
    policy: &Policy, rd: &RunDescriptor) -> RunOutcome;
```

> **Contract — commit and dissolution:** "a connection event ends in exactly one of three
> legitimate outcomes. Silent loss is not a legitimate outcome."

**Current — Phase 5 partial, with a disclosed placement correction:** `RunOutcome` (the real
3-variant enum) and `RunOutcome::resolve(gate_report, stitches, focus, replay, audit) -> Self`
now exist in `crates/ssk-runtime/src/lib.rs` — **not** `ssk-types` as originally suggested,
for the same reason as Section Q's correction: `Pass.focus: FocusReport` means this type can
only live somewhere that already depends on both `ssk-focus` and `ssk-types`, and `ssk-types`
cannot depend on `ssk-focus` without a cycle. `resolve` correctly maps all five
`GateOutcomeKind` values (`Pass` → `Pass`; `Hold`/`Refine` → `HoldRefine`; `Reject`/
`Quarantine` → `DissolveRejectQuarantine`), tested against all three branches.

**Not yet done, disclosed:** `RunOutcome` is not wired into any live call site —
`Runtime::run_once_with_context` still returns the older flat `RuntimeOutcome`/`ReplayManifest`
pair unchanged. A genuine `Pass` variant needs a real `FocusReport`, which needs real
`Response` evidence — and no `FiberExecution`/`ResponseCapture` pipeline stage exists anywhere
in this workspace to produce that evidence (ch. 14.1's spine names both stages, but nothing
implements them). Wiring `RunOutcome` in before those stages exist would mean fabricating
`Response` data, which this document declines to do. The module-level
`pub fn run_once(intent, state, policy, rd) -> RunOutcome` free function matching the PDF's
exact signature, and the four new `PipelineStep` variants (`PchPlacement`, `GabrielEvaluation`,
`CapabilityCheck`, `LinkabilityResidue`), remain unimplemented for the same reason plus one
more: `GateVector::evaluate` is currently one atomic call producing one `GateReport` — exposing
separately-traceable per-check pipeline stages needs that call broken apart, which was judged
too large a change to land safely alongside this phase's other work.

---

## S. Configuration Model

**PDF ref: Ch. 21.** Lands in `ssk-config`.

PDF (Ch. 21, verbatim YAML shape):

```yaml
system:
  name: ScorpioSync-Kaleidoscorp-Omega
  fail_closed: true
  mode: research_testbed   # personal | enterprise | research_testbed | agent
core:
  canonicalization: deterministic
  signature_policy: core_boundary_residue
  expose_core_address: false
locator_plane:
  allowed_types: [direct_ip, vpn_exit, proxy_exit, relay, gateway, multi_hop_path, local_overlay]
  require_locator_reality_check: true
  single_ip_external_privacy_claim: forbidden
projective_connection_hypercube:
  axes: [identity, locator, protocol, timing, trust, risk, capability, replay, boundary]
  require_all_axis_projection: true
hypertorus:
  dimension: 7
  phase_axes: [identity, locator, protocol, timing, risk, replay, focus]
  mode: deterministic   # or: seeded
  deterministic_replay: true
bcik:
  require_seam: true
  require_boundary_operator: true
  closure_threshold: 0.0
  tolerated_residue_threshold: policy_defined
capabilities:
  witness_required: true
  allowed_witnesses: [signature, token, zk_style, policy_cert]
  require_scope_and_expiry: true
privacy:
  adversary_model: partial_network_observer
  linkability_threshold: policy_defined
  require_residue_report: true
gates:
  order: [core, mirror, locator, bcik, pch, capability, fiber, privacy, boundary, focus, replay, dissolution]
  failure_policy: no_materialization
  hold_policy: diagnosable_non_persistent
replay:
  run_descriptor_required: true
  deterministic_materialization_required: true
ledger:
  append_only_audit: true
  store_payload: false
  store_trace_hash: true
dissolution:
  ttl_required: true
  finalize_residues_on_expiry: true
```

**Current:** `AppConfig{version, policy, runtime, interop}` (`crates/ssk-config/src/lib.rs:108-114`)
covers roughly 4 of the ~30 fields above, across none of the PDF's dedicated
`locator_plane`/`projective_connection_hypercube`/`hypertorus`/`bcik`/`capabilities`/`privacy`/
`gates`/`replay`/`ledger`/`dissolution` sections (the closest analog, `policy.gate_profile`,
only carries `order`+`fail_closed`).

**Design: breaking, full schema extension** via the existing migration pattern
(`parse_with_migration_yaml`/`toml`, `LoadedConfig.migrated_from`,
`crates/ssk-config/src/lib.rs:189-235`). **Naming decision (must be made once, here, not
discovered mid-implementation):** this schema is a distinct type from the Desktop track's
planned `AppConfigV3` product/profile schema (Section C). Recommend this document's schema stay
under the existing `AppConfig` type name, bumping `CURRENT_CONFIG_VERSION` from `2` to `3` for
*this* schema's purposes — and recommend the Desktop doc's product schema, when it lands,
either pick a different version number track or a wholly distinct type
(e.g. `ProductProfileConfig`) rather than colliding on the name `AppConfigV3`. This document
does not implement the Desktop doc's schema and takes no further position on its naming beyond
flagging the collision risk explicitly.

---

## T. Error & Fault Vocabulary Unification

Cross-cutting; see Section E.5 for the full design. Summary: `FaultKind` (18 variants, Section
P) lands in `ssk-types` as the canonical vocabulary; foundation-crate public APIs return it
directly; crates with genuine I/O-shaped errors keep their richer local enum plus a `From`
bridge at the boundary.

---

## U. Guarantees, Non-Goals, and Forbidden Claims

Mirrors `docs/DESKTOP_CLIENT_ARCHITECTURE.md` Section L, extended into the core layer. The
PDF's own normative non-goals (Ch. 1.3, verbatim) apply directly and are restated here so a
reader of either document sees the same non-claims stated the same way:

- **No magic address creation.** Mirror facets never synthesize public IP addresses. External
  locator plurality exists only when real egress resources exist (Section G.1).
- **No untraceability and no absolute anonymity.** The runtime reduces bounded, declared
  linkability under a declared adversary model; it does not defeat network reality (Section O).
- **No covert-channel, no traffic-obfuscation-for-evasion, no censorship-circumvention
  tooling.** A locator is a typed egress/transport resource, not an evasion device.
- **No self-designed cryptography.** The runtime consumes cryptographic primitives only through
  abstract provider traits backed by established, audited implementations (Section L).
- **No silent loss.** Every unresolved component of a crossing becomes a typed, visible residue
  (Section J's `ResidueRegister`).

Extended into this document's own scope:

- Real network I/O for `LocatorAdapter` (Section G.1) stays exclusively `ssk-netcore`'s
  (Desktop track's) responsibility — see Section X.
- No estimator implemented under Section O may ever claim resistance to
  `AdversaryModel::GlobalPassiveObserver` — a normative non-claim per the PDF's own axiom (Ch.
  15.2), not an omission to fix later.

---

## V. Implementation Phases mapped to SSKΩ-0..9

Current honest ceiling: SSKΩ-2, bordering SSKΩ-3 (Section D). Phases below close SSKΩ-3
through SSKΩ-9, in dependency order:

- **Phase 0 — Foundation Hardening** (prerequisite; not itself a new SSKΩ claim, but blocks
  everything after it). Section E in full: `Digest([u8;32])`+`content_id!`, sealed
  `CoreObject`, `Connection<S>` **skeleton** (stub transition bodies), `SecretBytes`,
  `FaultKind` vocabulary. *Why first:* every later struct signature (`BcikStitch`,
  `CapabilityWitness`, `StitchEdge`) is specified in terms of `content_id!`-derived ids.
- **Phase 1 — Domain Model + Scheduler completion** (→ finishes SSKΩ-1/2 to the letter).
  Sections F and H in full: full `CoreNode`/`MirrorFacet` fields, real `MirrorOrbit`,
  `birefract()`/`IdentityRay`/`LocatorRay`, 9-variant `LocatorFacet`,
  `LocatorAdapter`/`LocatorPool` trait + real `claims_external_plurality()` (Section G.1),
  `SchedulerMode`/`SchedulerSeed`/`HypertoroidalScheduler`/`visible()`. *Why bundled:*
  `visible()` is PCH's stated necessary precondition (Phase 3); `LocatorFacet` must exist
  before `BcikStitch` can reference a `LocatorId` meaningfully typed the new way.
- **Phase 2 — BCIK real crossing kernel** (→ SSKΩ-3). Sections J and L in full:
  `CapabilityWitness` struct + `CapabilityWitnessProvider` (Signature-kind via existing
  Ed25519) + `KeyAgreementProvider` (x25519, zero new deps), `BcikStitch`,
  `CrossOutcome::Closed(BcikStitch)`, `ResidueRegister` + full `BoundaryResidue`. *Why this
  order:* `CapabilityWitness` must exist before `CapabilityGate` can check anything real
  (Phase 3); this phase delivers the struct. `BcikStitch`'s payload must exist before
  Hypercube placement (Phase 3) can reference it; this phase delivers the payload.
- **Phase 3 — Gate Vector + PCH + Gabriel** (→ SSKΩ-4). Sections I and K in full: `Hypercube`/
  `Gabriel` modules (in `ssk-gates`), twelve real per-gate evaluators (now consuming real
  `CapabilityWitness` and real `BcikStitch`/PCH check), the `GateVector::evaluate` early-break
  fix, richer `GateProfile`. The early-break fix itself can land independently, ahead of the
  rest of this phase, as a standalone correctness patch.
- **Phase 4 — Persistent Stitch Tensor + typestate wiring** (→ SSKΩ-5). Section M in full:
  `StitchTensor`, `apply_sorted`, `StorageBackend` (bridging existing
  `GenericLedgerBackend<E>`), `StitchGraph`/`Accepted`. This is where `Connection<S>`'s `gate`/
  `materialize` transitions (Section E.3) get real bodies, since gates (Phase 3) and tensor
  (this phase) now both exist.
- **Phase 5 — Focus + Replay + RunOutcome** (→ SSKΩ-6). Sections N, Q, R in full:
  `FocusEngine`/`FocusReport`/`CoreSessionClass`, real `LinkabilityEstimator`/`AdversaryModel`/
  `LinkabilityReport` (Section O, needed by `FocusReport`), shared-pipeline-extraction real
  `ReplayEngine`, 3-variant `RunOutcome`, the four new `PipelineStep` stages.
- **Phase 6 — Locator pool + funnel-DAG** (→ SSKΩ-7). Section G.2 in full: `StitchEdge`/
  `LocatorGraph`/`HyperEdge`/`select_path`, real but **non-network** (local-overlay/
  test-harness only) egress adapters behind an `async` feature, health probing. Stays out of
  the Desktop track's `ssk-netcore` territory (Section X).
- **Phase 7 — Faultscan + Simulation + Conformance testbed** (→ SSKΩ-8). Section P in full:
  18-variant `FaultKind` + `Faultscan` trait, `ChaosFaultKind` rename landed alongside,
  concrete `LinkabilityEstimator` metric tests (locator reuse, timing concentration,
  cross-facet correlation, residue-visibility completeness — PDF Ch. 18.4), full deterministic
  test-vector suite + the property obligations quoted verbatim in Section W.
- **Phase 8 — Production hardening** (→ SSKΩ-9). Section S in full: real dissolution/TTL
  sweep (today `ttl_epoch` is just an `== 0` check, no sweeping), full 12-section config
  schema, config validation invariants, ledger verification hardening, this document's own
  Section U/X as the documented-limits deliverable.

---

## W. Test Matrix

Representative acceptance criteria per phase (mirroring `docs/DESKTOP_CLIENT_ARCHITECTURE.md`
Section M's gate-command style):

- **Phase 0 AC:** `cargo test -p ssk-types` proves `content_id!(X)::of(&provider, bytes)` is
  deterministic (`d1 == d2` for identical bytes) and `Digest`'s serde round-trip is still a hex
  string (no downstream JSON format break). `cargo test -p ssk-core` — a `trybuild`
  compile-fail test proves `Connection<Intent>` cannot reach `materialize` without passing
  through every intermediate state.
- **Phase 1 AC:** `cargo test -p ssk-locator` — `StaticLocatorPool` with a single `LocalOverlay`
  facet asserts `claims_external_plurality() == false`; a pool with two distinct live facets
  asserts `true`. `cargo test -p ssk-scheduler` — `visible()` proptest against the literal
  toroidal-distance formula (Ch. 7.2).
- **Phase 2 AC:** `cargo test -p ssk-crypto --features crypto` — new
  `capability_witness_vectors.rs`: issue → verify round-trip passes; tampered proof bytes fail
  verify; an expired witness (`epoch` mismatch) fails verify. `cargo test -p ssk-bcik` —
  `cross()` on a facet/locator pair with real seam data returns
  `CrossOutcome::Closed(BcikStitch)` with all fields populated; an incomplete boundary returns
  `Residue` with `severity`/`origin`/`open_obligation` populated, never a placeholder.
- **Phase 3 AC:** `cargo test -p ssk-gates` — a counting-projector spy proves
  `GateVector::evaluate` visits **all twelve gates** even after an early `Reject`;
  `hypercube_gate` proves `HypercubeGate` rejects when any of the 9 axes is
  `Projection::Undefined`/`Inconsistent`/`ReplayGap` and **holds** (not rejects) on
  `OverBudget` — matching Ch. 8.2's invariant literally.
- **Phase 4 AC:** `cargo test -p ssk-tensor -- tensor_preservation` proves
  `apply_sorted(vec![])` leaves `head()` unchanged, and a `trybuild` compile-fail test proves
  there is no public path from `Placed`/`Split` to `StitchTensor::apply_sorted` — the literal
  PDF theorem (Ch. 12.2) as an executable test.
- **Phase 5 AC:** `cargo test -p ssk-replay -- replay_determinism` — two independent
  re-executions of the same `RunDescriptor` produce bit-identical `ReplayVerdict::Deterministic`,
  and a single-bit input mutation produces `ReplayVerdict::Divergent{first_diff,...}` naming
  the *actual* diverging `PipelineStep` — proving the pipeline was really re-executed, not
  diffed from two pre-baked values.
- **Phase 6 AC:** `cargo test -p ssk-locator -- funnel_dag` — a `StitchEdge` missing any of
  `id, lifetime, policy_reason, map, boundary, trace` fails deserialization and cannot enter
  the `LocatorGraph` (Ch. 6.3's edge-explicitness invariant).
- **Phase 7 AC:** `cargo test -p ssk-faultscan -- no_silent_loss` implements Ch. 18.3's exact
  `proptest!` obligation verbatim:
  ```rust
  proptest! {
      #[test]
      fn no_silent_loss(x in crossing_with_unresolved_component()) {
          let out = bcik().cross(&x.facet, &x.locator, x.fiber, &policy());
          prop_assert!(matches!(out, CrossOutcome::Residue(_)) || out.residues_nonempty());
      }
  }
  ```
  `cargo test -p ssk-privacy -- residue_visibility_completeness` proves every
  `high_risk_components` entry in a `LinkabilityReport` has a matching `ResidueRegister` entry.
- **Phase 8 AC:** `cargo test -p ssk-config -- schema_v3_migrates` (v2→v3 migration,
  `migrated_from: Some(2)` recorded). Standing bar for every phase, as in the Desktop doc's own
  Phase 1: `cargo test --workspace` and
  `cargo clippy --workspace --all-targets -- -D warnings` green.

---

## X. Deliberately Deferred / Out-of-Scope Elements

- **Real network I/O for `LocatorAdapter`** (Section G.1/G.2). This document's Phase 6 adapters
  must stay local-overlay/mock/test-harness only and must **never** open a real socket — that
  is exclusively `ssk-netcore`'s (Desktop track's) responsibility. Any `HealthStatus` this
  document's code reports that isn't backed by a genuine probe must default to `Unknown`, never
  fabricate `Live`/`Degraded` — a direct extension of the Desktop doc's own forbidden-claims
  discipline (its Section L.3) into the core layer, disclosed here because it is a real risk:
  without this explicit discipline, a `HealthStatus` field could accidentally start lying the
  same way the pre-Phase-1 attestation claims did.
- **`ZkStyle`/`Token`/`PolicyCert` capability-witness kinds** (Section L). Only `Signature`-kind
  `CapabilityWitnessProvider` gets a real implementation. The other three `WitnessKind` variants
  are documented-but-unimplemented, returning a typed "not supported in this build" error.
- **`AdversaryModel::GlobalPassiveObserver`** (Section O/U). The enum variant exists per the
  PDF's own table, but no estimator in this codebase may ever claim resistance to it.
- **`async`/tokio in the decision core.** The PDF's Ch. 19.1 permits async at
  locator-adapter/probe edges. This document declines to introduce `tokio` into any of these
  core crates even for Phase 6's adapter/probe work — keeping `probe()` synchronous defers real
  async I/O entirely to the Desktop track's already-established "tokio lives only in new `std`
  product crates" invariant (`docs/DESKTOP_CLIENT_ARCHITECTURE.md` Section E.1). Introducing
  async here would contradict a positive, already-verified property of the workspace ("zero
  `async fn`", confirmed by that document's own grep) for no phase-relevant benefit.
- **Mandatory blockchain / global anonymity / untraceability.** Already non-claims per the
  PDF's own Ch. 1.3/24.2 — restated here purely so a reader of either document sees the same
  non-claims stated the same way.
- **`ssk-config`'s version-identifier collision with the Desktop track's `AppConfigV3`.**
  Resolved in Section S: this document's schema keeps the `AppConfig` name and moves to version
  3 for its own purposes; the Desktop track's product schema, when it lands, must pick a
  non-colliding name.

---

## Y. Agent Implementation Prompt

A standalone, directly-usable prompt for the coding agent that will implement this
architecture is maintained separately at **`docs/OMEGA_AGENT_IMPLEMENTATION_PROMPT.md`**. It is
scoped to start at Phase 0 and carries the same quality guardrails as
`docs/AGENT_IMPLEMENTATION_PROMPT.md`: no dummies, no throwaway MVP, every current-state claim
file-cited, fail-closed everywhere, strict literal PDF conformance. Use that file verbatim to
kick off implementation.

---

### Quality rules honored by this specification

- No dummies: every target component quotes the PDF's own signature or is explicitly marked as
  this document's own placement decision where the PDF is silent.
- No invented existing features: every "current state" claim cites a repository file:line,
  re-verified directly against source at the time of writing (not carried over unchecked from
  an earlier pass).
- No beyond-spec invention: every target signature is either a verbatim PDF quote or clearly
  marked as this document's own design decision (crate placement, naming collision resolution).
- Strict conformance discipline: this document targets exactly SSKΩ-4 through SSKΩ-9 as the PDF
  itself defines them (Ch. 22), building on a prerequisite pass (Phases 0-2) that finishes
  SSKΩ-0 through SSKΩ-3 to the letter.
- No silent loss (of scope): every deferred element is named explicitly in Section X, not
  silently dropped.
