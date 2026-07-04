# Agent Implementation Prompt — Kaleidoscorp Ω Core Conformance

> Copy the block below verbatim as the kickoff instruction for the coding agent that will
> implement this work. It is self-contained and references
> `docs/OMEGA_CORE_CONFORMANCE_SPEC.md` as the single source of truth, which in turn is a
> literal, section-by-section implementation of
> `ScorpioSync-Kaleidoscorp-Omega-Rust-Master-Spec.pdf` (the PDF). It is scoped to start at
> **Phase 0**, then hands off to later phases in order.

---

## Prompt (give this to the implementing agent)

You are implementing the pure decision-modeling core layer that turns the
ScorpioSync-Kaleidoscorp Ω repository's honest MVP into a literal, testable implementation of
its own formal master specification. Read `docs/OMEGA_CORE_CONFORMANCE_SPEC.md` first and treat
it as authoritative — it contains the full target architecture (sections A–Y), the verified
current-state inventory with file:line evidence, every target type/trait signature quoted
verbatim from the PDF, the phase sequence mapped to the PDF's own SSKΩ-0..9 conformance ladder,
and the guardrails on what stays deliberately out of scope.

### Ground truth about the repo (do not re-litigate; verify by file if unsure)

- The core crates (`ssk-types`, `ssk-core`, `ssk-scheduler`, `ssk-identity`, `ssk-locator`,
  `ssk-stitch`, `ssk-bcik`, `ssk-gates`, `ssk-tensor`, `ssk-focus`, `ssk-replay`,
  `ssk-faultscan`, `ssk-privacy`, `ssk-crypto`, `ssk-config`, `ssk-runtime`) currently sit at an
  honest conformance ceiling of **SSKΩ-2, bordering SSKΩ-3** (`docs/OMEGA_CORE_CONFORMANCE_SPEC.md`
  Section A/D). Ids are opaque strings, not content-addressed; there is no typestate machine;
  `BcikStitch` does not exist and `CrossOutcome::Closed` carries no payload; the twelve gates
  are mostly single-boolean-flag checks; the Hypercube, Gabriel cells, real `CapabilityWitness`,
  `FocusEngine`, and `LinkabilityEstimator` are entirely absent.
- A separate, already-implemented track (`docs/DESKTOP_CLIENT_ARCHITECTURE.md`, Phases 1-2 done)
  owns the daemon, IPC, and a future real network data plane (`ssk-netcore`/`ssk-capture`, not
  yet built). **Never duplicate that track's scope.** Your locator-adapter work
  (`OMEGA_CORE_CONFORMANCE_SPEC.md` Section G, Phase 6) stays strictly non-network — real
  sockets are exclusively `ssk-netcore`'s job.
- Real `SignatureProvider`/`AeadProvider` crypto already exists in `ssk-crypto`
  (`Ed25519KeyPair`, `ChaCha20Poly1305Provider`, behind the `crypto` feature) from that prior
  track — reuse it; do not reimplement ed25519 or ChaCha20-Poly1305.
- The already-real `GenericLedgerBackend<E>`/`LedgerBackend` disk-persistence infrastructure in
  `ssk-tensor` (also from that prior track) is the correct foundation for Section M's
  `StorageBackend` — bridge it with a supertrait, do not fork it.

### Absolute rules

1. **Strict literal conformance.** Every new type, trait, and field name must match the PDF's
   own Rust signatures, quoted verbatim in `docs/OMEGA_CORE_CONFORMANCE_SPEC.md`. Where the PDF
   is silent (crate placement for PCH/Gabriel, a config version-number collision), the spec
   states the decision explicitly — follow it, don't improvise a different one.
2. **No attrappen / no throwaway MVP.** Every component does real, testable work matching its
   PDF-specified contract. A stub is acceptable only where the spec itself says so (e.g. Phase
   0's `Connection<S>` transition bodies are deliberately stubbed until their dependency phase
   lands — this is documented, not hidden).
3. **Fail-closed everywhere.** No gate, no crossing, no capability check may default to "pass"
   on missing or malformed input. `CrossOutcome` has no unit success variant. A residue is
   emitted for every unresolved component — no silent loss (PDF Ch. 1.3, restated in Section U).
4. **No forbidden claims.** Never let a `HealthStatus`, `LinkabilityReport`, or
   `claims_external_plurality()` implementation report something that isn't real (Section
   U/X). `AdversaryModel::GlobalPassiveObserver` resistance is never claimed by any estimator.
5. **`#![forbid(unsafe_code)]`** stays on every crate touched — none of this work needs
   `unsafe`.
6. **Additive where the spec says additive; breaking only where the spec says breaking** (each
   section states which). When a change is breaking, fix every call site in the same commit —
   do not leave the workspace in a non-compiling state between commits.
7. Every new capability ships with tests as specified in Section W. Do not mark a phase done
   until its stated acceptance criteria pass.
8. Run `cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings &&
   cargo test --workspace` before declaring any phase complete — this mirrors CI's
   `fmt_lint`/`build_test` jobs.

### Phase 0 — Foundation Hardening (start here)

- `ssk-types`: `Digest([u8; 32])` + `content_id!` macro (Section E.1); keep `serde` output as a
  hex string so `GenericFileLedgerBackend`'s on-disk JSON format doesn't need a migration.
  `FaultKind` (the PDF's 18-variant taxonomy, Section P) added as the canonical vocabulary.
- `ssk-core`: extend `SealedCoreObject` → `CoreObject` with `object_kind()`/`residue_policy()`
  (Section E.2); land the `Connection<S>` typestate skeleton (Section E.3) with stub transition
  bodies — do not attempt to fill in `birefract`/`place`/`gate`/`materialize` bodies yet, those
  belong to Phases 1-4.
- `ssk-crypto`: add `SecretBytes` (Section E.4), promoting `zeroize` from transitive to direct.
- **AC:** `content_id!` is deterministic and produces the same id for identical canonical bytes;
  a `trybuild` compile-fail test proves `Connection<Intent>` cannot reach `materialize` without
  passing through every intermediate state; `cargo test --workspace` still green with zero
  behavior change to existing call sites (Section E.1's hex-string serde compatibility is what
  makes this possible).

### Then Phase 1 — Domain Model + Scheduler completion

- `ssk-types`/`ssk-core`: full `CoreNode`/`MirrorFacet` fields (Section F.1), real
  content-addressed `MirrorOrbit::derive/recover` (Section F.2), `birefract()`/`IdentityRay`/
  `LocatorRay` with no `From`/`Into` between the two ray types (Section F.3), 9-variant
  `LocatorKind`/`LocatorFacet` (Section F.4).
- `ssk-locator`: `LocatorAdapter`/`LocatorPool` traits, existing concrete struct renamed to
  `StaticLocatorPool`, **real** `claims_external_plurality()` — must return `false` honestly
  for a single-`LocalOverlay`-pool configuration (Section G.1).
- `ssk-scheduler`: `SchedulerMode`/`SchedulerSeed`/`HypertoroidalScheduler` rename, real
  `visible()` toroidal-distance predicate (Section H) — add `rand_pcg` for seeded jitter.
- **AC:** Section W's Phase 1 tests — plurality claim proven false/true against 1-facet vs.
  2-facet pools; `visible()` proptest against the literal toroidal-distance formula.

### Then Phase 2 — BCIK real crossing kernel

- `ssk-crypto`: `CapabilityWitnessProvider::WitnessKind::Signature` built on the existing
  `Ed25519KeyPair` (Section L); `KeyAgreementProvider` (x25519, `x25519-dalek` is already an
  unused optional dependency — zero new deps).
- `ssk-types`: `CapabilityWitness` struct replaces `capability_witness: bool`.
- `ssk-bcik`/`ssk-types`: `BcikStitch` payload, `CrossOutcome::Closed(BcikStitch)`,
  `ResidueRegister` + full `BoundaryResidue` (severity/origin/open_obligation) (Section J).
- **AC:** capability issue→verify round-trip; tampered proof and expired witness both fail
  verify; `cross()` on real seam data returns a fully-populated `BcikStitch`.

### Then Phase 3 — Gate Vector + PCH + Gabriel

- `ssk-gates`: `ssk-gates::pch` and `ssk-gates::gabriel` new modules (Section I); twelve real
  gate structs replacing `BasicGate`'s single match (Section K); fix `GateVector::evaluate`'s
  early-`break` (this alone can land as an isolated first commit within this phase).
- `ssk-config`: richer `GateProfile` (thresholds, required_evidence, failure_policy,
  hold_policy, pass_policy).
- **AC:** a counting-projector spy proves all twelve gates fire even after an early Reject;
  `HypercubeGate` rejects on Undefined/Inconsistent/ReplayGap, holds (not rejects) on
  OverBudget.

### Then Phase 4 — Persistent Stitch Tensor + typestate wiring

- `ssk-tensor`: `StorageBackend` as a supertrait of the existing `GenericLedgerBackend<E>`
  (bridge, don't fork); `StitchTensor`/`apply_sorted`/`StitchGraph`/`Accepted` (Section M).
- `ssk-core`: fill in `Connection<GatePassed>::materialize`'s real body now that both gates
  (Phase 3) and tensor (this phase) exist.
- **AC:** the tensor-preservation theorem as a literal test (`apply_sorted(vec![])` leaves
  `head()` unchanged) plus a `trybuild` compile-fail test proving no public path from
  `Placed`/`Split` to `apply_sorted`.

### Then Phase 5 — Focus + Replay + RunOutcome

- `ssk-privacy`: `LinkabilityEstimator`/`AdversaryModel`/`LinkabilityReport`, wrapping the
  existing heuristic as `HeuristicLinkabilityEstimator` (Section O).
- `ssk-focus`: `FocusEngine`/`FocusReport`/`CoreSessionClass` (Section N) — depends on the
  above and on Section Q.
- `ssk-core`/`ssk-replay`: extract the shared decision-core pipeline into
  `ssk_core::pipeline::execute_once`; rewrite `ReplayEngine` to genuinely re-execute and diff
  (Section Q).
- `ssk-types`/`ssk-runtime`: 3-variant `RunOutcome`, new `PipelineStep` stages (Section R).
- **AC:** bit-identical re-execution replay proving genuine determinism, not diffed equality;
  a single-bit input mutation produces a `Divergent` verdict naming the real diverging stage.

### Then Phase 6 — Locator pool + funnel-DAG

- `ssk-locator`: `StitchEdge`/`LocatorGraph`/`HyperEdge`/`select_path` (Section G.2) — depends
  on Hypercube (Phase 3). Adapters stay **non-network** — see the absolute rules above and
  Section X. `HealthStatus` defaults to `Unknown` unless backed by a genuine local probe.
- **AC:** a `StitchEdge` missing any required field fails deserialization and cannot enter the
  graph.

### Then Phase 7 — Faultscan + Simulation + Conformance testbed

- `ssk-faultscan`: rename existing 6-variant enum to `ChaosFaultKind`; add the real 18-variant
  `FaultKind` (already added to `ssk-types` in Phase 0) + `Faultscan` trait with a `scan()`
  implementation deriving `FaultEvent`s from real runtime signals (Section P).
- Property tests from the PDF Ch. 18.3 verbatim (`facet_recovers_to_core`,
  `failed_gate_preserves_tensor`, `no_silent_loss`) plus the privacy metric tests (Ch. 18.4).
- **AC:** `no_silent_loss` proptest passes; every `LinkabilityReport.high_risk_components` entry
  has a matching `ResidueRegister` entry.

### Then Phase 8 — Production hardening

- `ssk-config`: full 12-section YAML schema (Section S) under the existing `AppConfig` type
  name at version 3 (the naming decision is already made in the spec — do not introduce
  `AppConfigV3`, that name is reserved for the separate Desktop track's product schema).
- Real dissolution/TTL sweep (today just an `== 0` check).
- **AC:** v2→v3 config migration test; full `cargo test --workspace` +
  `cargo clippy --workspace --all-targets -- -D warnings` + `cargo deny check` +
  `cargo audit --deny warnings` green — this is the final gate for the whole document.

### Deliverable discipline

- Keep commits scoped per phase (or per clearly-labeled sub-step within a phase, e.g. the
  `GateVector::evaluate` early-break fix) with descriptive messages.
- Update `docs/OMEGA_CORE_CONFORMANCE_SPEC.md`'s Section A/B/D status tags only to correct a
  current-state claim you have made obsolete by shipping the corresponding component — do not
  edit `docs/DESKTOP_CLIENT_ARCHITECTURE.md` or `docs/AGENT_IMPLEMENTATION_PROMPT.md`, they
  belong to the separate, already-complete daemon/IPC track.
- Stop and surface a decision to the user only when the PDF is genuinely ambiguous about a
  signature or a crate boundary that this document's own Section X/G/S decisions don't already
  resolve; otherwise implement the specified literal path.
