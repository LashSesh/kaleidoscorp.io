# IMRT → SSK Implementation Specification

> **Provenance & method.** Derived from `IMRT_Master_Spezifikation_Fassung_1_1.pdf` (the pure theory) by an
> exhaustive theory→code conformance pass: six clusters mapped every axiom / base object / validity predicate to
> the codebase, each mapping was then independently re-checked by a skeptic against the actual source (no
> "Realized" claim survives without cited `crate::symbol` evidence), and the result was synthesized into the 63
> verified rows below. The load-bearing divergences (A6 gate axes, A7 closure, A8 atlas) were additionally hand-
> verified against the code. No wall-clock date is stamped — the workspace uses logical time; version this
> document by the theory version it targets (**Fassung 1.1**) and the git commit it lands on.
>
> **Scope of this turn: specification only.** No code was written or changed to produce this document. The gap
> list (§5) is the proposed work for a follow-up implementation pass, to be undertaken only after review.

## 1. Title & Purpose

This document is an **implementation specification** that bridges the pure formal theory
**IMRT — Immersive Mirror Reference Theory** (source of truth: `IMRT_Master_Spezifikation_Fassung_1_1.pdf`,
the "Fassung 1.1" master spec) to the existing Rust codebase of the **SSK / ScorpioSync-Kaleidoscorp**
workspace (`/home/user/kaleidoscorp.io`, ~41 crates under `crates/`).

It records, per theory element, **how faithfully the code enforces the theory's invariant** — not merely
whether a similarly-named type exists. Verdicts are drawn from a verified conformance map that cites exact
`crate::symbol` (and `file:line`) evidence.

> **This is a SPECIFICATION, not implemented change.** No code is written or modified here. Every "task"
> below is a proposed obligation for a follow-up implementation pass. Where the code already conforms, this
> document says so plainly with evidence; where it diverges, the verdict is stated without softening.

The theory's normative core is: 10 axioms **A1..A10** (§10), ~30 base objects with signature+invariant+residue
(§8, Table 6), an operator algebra with proven properties (§9), and a 14-conjunct validity formula
**IMRTValid(x)** (§19) whose every conjunct is bound to an axiom, definition, or theorem.

### Verdict vocabulary

| Verdict | Meaning |
|---|---|
| **Realized** | The code genuinely enforces the theory's invariant (type-level or tested), not just the name. |
| **Partial** | The name/shape is present but the invariant is weaker, untested, or missing fields/proofs. |
| **Divergent** | A type exists but its invariant is *different* from the theory's (e.g. axis re-purposed). Reported honestly. |
| **Absent** | No object realizes the element; grep-confirmed. |

### Corpus roll-up (63 verified rows)

This is the **as-audited baseline** (the state at spec authoring time):

| Realized | Partial | Divergent | Absent | Total |
|---:|---:|---:|---:|---:|
| 24 | 22 | 8 | 9 | 63 |

**Implementation pass 1** has since closed 25 of the ranked gaps (G1, G2, G3, G4, G5, G6, G7, G8, G9, G10, G11,
G12, G15, G16, G17, G18, G24, G25, G26/G27, G28, G29, G30, G31, G34, G36), each with a discharging test on a
green workspace — see the §5a Resolution Log for the per-gap status and evidence. The baseline table above is
intentionally left unchanged as the audit-time snapshot; §5a is authoritative for current status.

---

## 2. IMRTValid(x) — Top-Level Conformance Checklist

The 14-conjunct validity formula (§19, Def. 19.1, Tab. 11):

```
IMRTValid(x) ⟺ SelfAnchored(x) ∧ NullReferenced(x) ∧ ObserverTyped(x)
             ∧ ApertureOrdered(x) ∧ SplitCoherent(x) ∧ ParallaxDeclared(x)
             ∧ WavefrontFormed(x) ∧ GateQualified(x) ∧ ResidueConserved(x)
             ∧ CounterHorizonMapped(x) ∧ FourPiClosedOrResidued(x)
             ∧ AtlasCrystallized(x) ∧ ReanalysisBound(x) ∧ BoundaryCompatible(x)
```

Each predicate's overall status is rolled up from the per-element rows (§4). Because IMRTValid is a
**conjunction**, the aggregate validity is gated by its weakest conjunct: today at least four conjuncts are
Divergent/Absent, so **IMRTValid(x) is not yet establishable end-to-end.**

| # | Predicate | Bound axiom / foundation | Rolled-up status | Basis |
|---|---|---|---|---|
| 1 | SelfAnchored | A1 | **Realized** | 7-tuple `SelfAnchor` with content-id `idcan`, non-locator invariant type-enforced. Anchor-drift *stability* (Vertrag 8.3) is separately **Divergent** (see G2). |
| 2 | NullReferenced | A1, Def. Z | **Absent** | No L0 `NullAnchor Z=(orderRef, recoveryRoot)`; grep-confirmed absent (G1). |
| 3 | ObserverTyped | A5, Def. O | **Realized** | `ObserverModel::new` is the sole constructor, fails closed on unauthorized. Field aggregate `ObserverField` is **Partial** (G25). |
| 4 | ApertureOrdered | A2, Prop. 9.2 | **Realized** | Focus unreachable from a closed aperture by type; Dump conservation tested. Algebra proofs (idempotent/contracting) untested (G36). |
| 5 | SplitCoherent | Def. Split (≥2 orthogonal) | **Partial** | `birefract` yields non-convertible Identity/Locator rays (Realized), but observation `BirefringentSplit` accepts identical wavefronts — permits the forbidden "mere copy" (G29). |
| 6 | ParallaxDeclared | A3, Inv. 9.6 | **Partial** | `Parallax` is a boolean/set from digest-inequality, not the pseudometric `d`; ≥2 distinct vantages not required (G28). |
| 7 | WavefrontFormed | Def. W, Satz 9.13 | **Realized** | `Wavefront` is a projection (not a physical wave), projection residue visible in `hidden_dimensions`; `asserts_physics=false`. |
| 8 | GateQualified | A6, Prop. 9.9 | **Divergent** | Fail-closed conjunction is genuinely realized, **but** the gate's input `QState` and 3 of 6 axis semantics diverge from `g=(κ,H,Π,R,B,Δ)` (G3, G4). Qualification runs against different quantities than the theory demands. |
| 9 | ResidueConserved | A4, Satz 13.5 | **Partial** | Run-level "no silent loss" approximated by an append-only bag; 5-tuple residue incomplete, taxonomy K short by 2 kinds, several residues Absent (G7–G13). |
| 10 | CounterHorizonMapped | A4, Def. H | **Partial** | `ResidueRegister` is a flat append-only Vec; the disjoint origin-edge partition (Def 11.6) and ρ* escalation are not enforced (G8, G10). |
| 11 | FourPiClosedOrResidued | A7, Satz 12.4 | **Partial** | Closure is digest-equality of two passes; the second Satz 12.4 conjunct (`[S]_can` preserved across 4π) is never evaluated and no Gegenhorizontmasse residue is emitted; the ℤ/2 rotor is Absent (G5, G6). |
| 12 | AtlasCrystallized | A8, Satz 15.4 | **Divergent** | The type named `SelfPerceptionAtlas` **is** the append-only Ledger Λ, not the 13-tuple Φ; missing ClaimSet/ParallaxMatrix/ClosureReport/X/H/ReanalysisState/BoundaryInterfaceFit (G14). |
| 13 | ReanalysisBound | A8, Satz 16.2 | **Partial** | `reanalyze` recovers the self-class (does not write 𝒮), but returns booleans not the `{Pass,ClassMismatch,Ambiguous}` verdict, no class-idempotence, no `w(Φ)` certificate (G17, G18). |
| 14 | BoundaryCompatible | A9, A10, Satz 18.4 | **Divergent** | The certifier `B(Φ,Shell)→Fit` is Absent and the 8-tuple `CompatibilityShell` is Divergent (the only "Compatibility" type is a wire-handshake negotiator). Border *objects* are mostly Realized, but the shell/certifier the axiom names are not (G19, G20). |

---

## 3. The Ten Axioms A1..A10

For each axiom: the **demand**, the **current enforcement** in the code, and a **verdict**.

### A1 — SelfAnchor-priority (identity is NEVER a locator)
- **Demand:** Every valid reconstruction originates in a canonical self-class `S`; `S` is type-distinct from and
  non-convertible into any locator (IP, fingerprint, device-id, VPN-exit, proxy, resolver, session-id); a
  prätemporal null fixpoint `Z` orders/recovers projections and is never materialized.
- **Enforcement:** `ssk-imdf::self_anchor::SelfAnchor` (7-tuple, content-id `idcan` under `SELF_ANCHOR_DOMAIN`),
  distinct newtypes `SelfAnchorId` vs `LocatorAddressId`, no `From`/`Into` either direction; `ssk-types::CoreNode`
  vs `LocatorFacet`, `IdentityRay` vs `LocatorRay` explicitly non-convertible (comment at
  `ssk-types/src/lib.rs:478`). Tests `self_anchor_is_not_locator`, `birefract_splits_into_an_identity_ray_and_a_locator_ray`.
- **Verdict:** **Realized at the identity/locator boundary** (structural non-identity is type-enforced and tested),
  **but incomplete at the L0 root**: the null fixpoint `Z` is Absent (G1) and anchor-drift stability (Vertrag 8.3)
  is Divergent (G2). Residual caveat: non-convertibility rests on the *absence* of a `From`/`Into` impl, not a
  compile-fail barrier.

### A2 — Aperture-before-focus
- **Demand:** No focus is valid before an aperture bounds the measurement space; dimensions outside the aperture
  become a visible Dump residue, never vanish.
- **Enforcement:** `ssk-imdf::aperture::ApertureSession::focus` is only reachable from an *open* aperture;
  `ObserverModel::open_aperture` errors `ApertureRequired` when closed; un-admitted dimensions push to both
  `hidden_dimensions` and a `ResidueReport`. Tests `aperture_before_focus_required`, `hidden_surface_becomes_residue`.
- **Verdict:** **Realized** for the ordering + Dump conservation. Weaker below the ordering: aperture algebra
  proofs (idempotent/contracting, Prop 9.2) untested (G36); `Lens` is inert metadata not the residue-forming
  operator (G35); the `ImmersionField`/`Immerse` aggregate is Absent (G32).

### A3 — Parallax obligation
- **Demand:** A finding stable in only one ray gains no gate relevance; parallax is a symmetric pseudometric over
  ≥2 role-orthogonal sight-paths (Inv 9.6).
- **Enforcement:** `ssk-core::birefract` returns non-convertible `IdentityRay`/`LocatorRay` (genuine role
  orthogonality). `ssk-imdf::wavefront::BirefringentSplit::parallax` computes shared/disagreement digest-sets.
- **Verdict:** **Partial.** The typed identity/locator split is orthogonal, but the *observation* split accepts
  identical wavefronts (the forbidden copy, G29), `Parallax` is boolean/set not a pseudometric `d` (G28), no
  `SplitAxis` discipline (G30), and ≥2 distinct vantages are not required before gate relevance.

### A4 — Residue conservation / No Silent Loss
- **Demand:** Every non-integrated field part is registered as a 5-tuple residue `(Source, Fragment, Reason,
  Status, NextAction)` in a class of the closed taxonomy K (11 kinds); the residue cloud X partitions into
  disjoint origin-edge classes (Def 11.6) with a ρ* catch-all (Inv 11.7); nothing is ever deleted.
- **Enforcement:** `ssk-types::ResidueRegister` (append-only Vec, only `emit`/`entries`/`open_obligations`),
  `BoundaryResidue`, `ResidueKind` (9 variants). Run-level test `no_silent_loss`
  (`ssk-runtime/tests/conformance.rs:77`), `residue_visibility_completeness_...` (`ssk-privacy`).
- **Verdict:** **Partial.** Append-only spirit met; the *totality* ("nothing silently lost") approximated. But:
  residue is a 5-tuple only in part — **Fragment and NextAction absent**, Status collapses to a bool (G9);
  taxonomy K missing **Cospectral** and **FieldProjection** (G9); the **disjoint edge-partition and ρ***
  are not enforced (G8); several concrete residues are Absent — HostAuthority (G7), Kontaktlücke (G34),
  Boundary-Ambiguität (G38), Kospektral-Hold payload (G11).

### A5 — Claim-gating
- **Demand:** An observer yields a Befund (finding), never Wahrheit; a claim carries weight iff
  `Ground≠∅ ∧ Gate defined ∧ Status∈{Pass,Hold,Fail} ∧ Residue declared` (Satz 14.5); an unauthorized observer
  must be impossible to construct.
- **Enforcement:** `ObserverModel::new` is the sole constructor and fails closed (`ImdfError::Unauthorized`)
  unless the manifest is valid for `SELF_OBSERVATION_USE`; `Reading::Blind`/`Measured` separates
  finding-not-truth; `QOutcome{Pass,Hold,Fail}` realizes the Status codomain. Tests
  `observer_without_authorization_fails`, `blindspot_is_not_reported_as_fact`.
- **Verdict:** **Realized** for observer-typing and unauthorized-impossible. **Divergent** for the Claim object
  itself: no `Claim` 8-tuple exists; `AtlasObservation` has 5 fields (no Predicate/Scope/Layer/Ground/Residue),
  so the Satz 14.5 weight predicate is neither expressible nor enforced (G24).

### A6 — Gate multidimensionality / fail-closed with g=(κ,H,Π,R,B,Δ)
- **Demand:** `G(x)=Pass ⟺ ∀G∈G: G=Pass`; a single mandatory Fail forbids materialization; the six axes carry the
  theory's specific meanings — **Π=projection-quality (Projektionsgüte), R=residue-load (|X(c)|/|M(c)|),
  B=boundary-stability**; the gate input is `q=(s,φ,κ,r)`.
- **Enforcement:** `ssk-imdf::qlogic::QLogicVector::verdict` (worst-of over six axes, no early break),
  `ssk-gates::GateVector::evaluate` (all 12 gates, fail-closed, residue-monotone, retains every non-pass residue).
  Tests `gate_vector_fail_closed`, `all_twelve_gates_are_evaluated_even_after_an_early_reject`,
  `gate_vector_is_not_single_score`.
- **Verdict:** **Realized fail-closed conjunction — but DIVERGENT axis semantics.** Only κ, H, Δ match the theory.
  The other three are re-purposed: **Π = `parallax_consistent`** (an A3 boolean, NOT projection-quality),
  **R = `replay_equal`** (replay, NOT residue-load), **B = `open_obligations==0`** (obligation count, NOT
  boundary-stability). The module doc itself (`qlogic.rs:8-10`) admits Π="parallax", R="replay", B="boundary
  obligation". The gate input `QState q=(s,φ,κ,r)` is also Divergent — the actual `QLogicInput` is an 8-field
  tuple with no band-occupancy `s`, no phase `φ`, no residue-mark `r`, and no `Stab(q)` orthogonal-kick probe.
  **This is the theory's flagged sensitive point, and it diverges.** (G3, G4.)

### A7 — 4π-closure (visible ≠ oriented return)
- **Demand:** A run is closed only after a second *oriented* return (4π); Satz 12.4 requires BOTH `ω²(c)=c` AND
  `[S after 4π]_can=[S before 4π]_can`; failure of the second conjunct yields Gegenhorizontmasse in 𝒳_FourPi.
  Orientation lives in a ℤ/2-graded bundle (2π acts as −1), realized by a Clifford rotor (Satz 12.8).
- **Enforcement:** `ssk-imdf::closure::FourPiClosure::is_closed = passes.len()>=2 && passes[0]==passes[1]`.
  Test `four_pi_requires_second_orientation_pass`.
- **Verdict:** **Partial, bordering Divergent.** Only the *count-structural* "a lone 2π pass is not enough" is
  enforced. There is **no ℤ/2 orientation sign-flip** (rotor Absent, G5), `OrientationPass` carries no relation
  to the `SelfAnchor` so the second Satz 12.4 conjunct is **never evaluated**, and a disagreeing pass merely
  stays `Open` with **no Gegenhorizontmasse residue** (G6).

### A8 — Reanalysis-binding
- **Demand:** Φ is reanalysable (not an endpoint) and carries a `ReanalysisState` referring it back to `S`;
  `Reanalyse` reconstructs a canonical class, is class-idempotent (Prop 9.12), certifies `S` without writing 𝒮;
  `w(Φ)=1 ⟺` replay-determinism ∧ reanalysis-success ∧ anchor-invariance-under-drift; a version-stage ratchet ℓ
  is non-falling with an idempotent reset 𝜚 (Satz 16.12/16.13); drift is governed by a double-threshold
  hysteresis (Satz 16.9), not a single threshold.
- **Enforcement:** `ssk-imdf::replay::reanalyze` (recovers a fresh `SelfAnchor` and compares its id — does not
  write 𝒮); `ssk-replay::DeterministicReplayEngine::replay` (re-executes and diffs, returns
  `Deterministic|Divergent`); `ssk-focus::FocusEngine::reanalyze` (`Pass|ClassMismatch|Ambiguous`). Tests
  `reanalysis_recovers_self_anchor`, `genuinely_re_executed_run_matches_its_own_manifest`.
- **Verdict:** **Partial-to-Absent, mixed.** Replay determinism is **Realized** (bit-exact, no silent input drop).
  But: Φ is not the 13-tuple and carries no `ReanalysisState` (Divergent, G14); `reanalyze` returns booleans not
  the typed verdict and has no class-idempotence guarantee (G18); the `w(Φ)` stability certificate is Absent
  (G17); the drift governor is a **single-threshold** point predicate — exactly the form Satz 16.9 proves wrong
  (Divergent, G15); and the version-stage ratchet + reset 𝜚 are Absent (G16).

### A9 — Boundary discipline (BoundaryInterface, not mixing)
- **Demand:** Connection is by interface / closure-object, never by mixing; every identity×locator crossing yields
  `Seam ∧ Boundary ∧ (Closure ∨ visible Residue)` — no silent crossing; at L9 a certifier `B(Φ,Shell)→Fit`
  certifies (does not mutate) an Atlas against the 8-component CompatibilityShell.
- **Enforcement:** `ssk-bcik::Bcik::cross` with `CrossOutcome = Closed(BcikStitch) | Residue(BoundaryResidue)`
  (no unit-success variant); `SeamWitness`, `BoundaryRecord`. Tests `cross_returns_residue_when_open`,
  `cross_returns_a_closed_stitch_with_populated_fields_...`.
- **Verdict:** **Partial.** The no-silent-crossing invariant is genuinely type-enforced **at single-crossing
  granularity**. But closure is decided from boolean candidate flags (`seam_ok`/`boundary_complete`) over empty
  Phase-2 placeholder structs (G22), and the whole apparatus is **never lifted to the Atlas/Anschluss
  granularity B governs** — the certifier `B` is Absent (G19).

### A10 — Semantic non-mixing with Ω
- **Demand:** No Ω term enters the IMRT core and vice versa; translations live ONLY at B, are logged, and any
  unfinished translation is a visible Interface-Residuum; five translation objects (SeamWitness, BoundaryRecord,
  GateMap, ReplayBridge, ResidueLift, Def 18.3) each carry Trace+Replay.
- **Enforcement:** `ssk-types::SeamWitness`, `BoundaryRecord`, `ResidueKind::Boundary` exist and are emitted.
- **Verdict:** **Partial → Divergent at the shell.** Two of five translation objects exist; **GateMap,
  ReplayBridge, ResidueLift are Absent** (G23); SeamWitness/BoundaryRecord do not each carry Trace+Replay; and
  the only `CompatibilityPolicy` type is a wire-handshake negotiator whose invariant is version/feature
  negotiation, **not** the eight axis-to-Ω boundary conditions (Divergent, G20). Term-collision on
  "Compatibility" itself risks the very mixing A10 forbids.

---

## 4. Per-Layer Conformance Table

Layers L0..L9 + operators + boundary. `theory_element | axioms | codebase_location | verdict | gap`.

### L0–L1 Foundation
| Theory element | Axioms | Codebase location | Verdict | Gap (short) |
|---|---|---|---|---|
| NullAnchor Z=(orderRef, recoveryRoot); Z∉LocatorPlane, ∉PublicSurface | A1 | *Absent* (nearest: `CoreNode.replay_root/audit_root`, `ssk-types/src/lib.rs:204`) | **Absent** | No L0 fixpoint; roots are freely-emitted content refs, no never-emitted invariant. |
| SelfAnchor S = 7-tuple | A1,A2 | `ssk-imdf::self_anchor::SelfAnchor` (`self_anchor.rs:28`) | **Realized** | `idcan` is a Blake3 content-id over the other six — stronger than a carried id. |
| SelfAnchor non-locator invariant | A1,A2 | `SelfAnchorId` vs `LocatorAddressId`, `BcikCrossing::record` (`self_anchor.rs:18,140`) | **Realized** | Non-convertibility rests on absence of `From`/`Into`; content of fields unvalidated (type-only). |
| Contract 8.3 Anchor-Stability (drift forks a new run) | A1,A8 | drift as QLogic Δ axis only (`qlogic.rs:85`); `RunDescriptor` has no run id/prior-trace (`replay.rs:18`) | **Divergent** | Drift consumed as a truth-filter, not a run-forking trigger; no new-trace-referencing-old mechanism. |
| MirrorDome apparatus (L1–L7); "Selbstbezug vor Fremdbezug" | A2,A3 | `ssk-imdf` module composition (`lib.rs:3-52`) | **Partial** | No binding apparatus object; self-before-foreign ordering not encoded. |

### L2–L4 Observation
| Theory element | Axioms | Codebase location | Verdict | Gap (short) |
|---|---|---|---|---|
| ObserverModel O_i (9-tuple) | A5 | `ssk-imdf::observer::ObserverModel` (`observer.rs:86`) | **Realized** | `allowed_inputs` missing; `trust` is a 3-level enum. A5 core enforced. |
| ObserverField O = {O_1..O_k} | A5,A3 | *Absent as aggregate* (only pairwise `BirefringentSplit`) | **Partial** | No k-observer set container; parallax wired only for m=2. |
| Blindspot residue (5-tuple) | A5,A4 | `observer::Blindspot=(region,reason)` (`observer.rs:60`) | **Partial** | Only 2/5 fields; MissingInstrument/Impact/RequiredAperture absent. Honesty invariant realized. |
| Aperture Focus/Dump conservation | A2,A4 | `aperture::ApertureSession::focus` (`aperture.rs:122`) | **Realized** | Closed aperture unfocusable by type; each hidden dim → residue. |
| Aperture algebra (idempotent/contracting/monotone) | A2 | `aperture::Aperture::admits` (`aperture.rs:51`) | **Partial** | Structural but never asserted by test; monotonicity not exposed. |
| Lens A⇀L×X (partial, residue-forming) | A2,A4 | `observer::Lens` (`observer.rs:40`) is inert metadata | **Partial** | `Lens` extracts nothing; Body⊔Res realized by `focus()`, not attributed to Lens. |
| SplitOperator (m≥2 orthogonal roles) | A3 | `wavefront::BirefringentSplit::of` (`wavefront.rs:77`); `ssk-core::birefract` | **Partial** | `BirefringentSplit` accepts identical wavefronts (the "mere copy"); m fixed at 2. |
| Split ≅ Ω-birefract (non-convertible rays) | A1,A3 | `ssk-types::IdentityRay`/`LocatorRay` (`lib.rs:454,483`) | **Realized** | Holds; rests on absent `From`/`Into` — add trybuild guard. |
| SplitAxis (enumerated 7 axes) | A3 | *No SplitAxis type*; 2 axes realized ad hoc | **Partial** | 2/7 axes; no enum; split does not declare its axis. |
| ParallaxOperator (symmetric pseudometric) | A3 | `wavefront::Parallax` (`wavefront.rs:60`); true metric unbound in `ssk-signature::global_distance` | **Partial** | Boolean/set, not `d`; Π gate axis = parallax-consistency ≠ theory Π. |
| ImmersionField IF + Immerse (total, injective) | A2 | *Absent*; traversal only functional in `ssk-system::SystemPipeline` | **Absent** | No S-anchored IF bundle; no Immerse operator. |
| FieldCell/HostCell non-routing invariant | A1 | `ssk-host-cells::{HostCell,HostCellPlane}` (`lib.rs:43,67`) | **Realized** | Ephemerality, non-identity, capability/scope binding all tested. |
| FieldCell fold (IMDF ⊕ FCHL) | A2 | Only FCHL half: `HostCell` (`ssk-host-cells/src/lib.rs:43`) | **Divergent** | No pos/observer/aperture/phase/coherence/residue/trace on the cell. |
| HostAuthority residue on under-capability | A4 | `HostCellPlane::can` returns bare `bool` (`lib.rs:177`) | **Absent** | Denial is a silent boolean, no residue emitted. |
| Ray = focused sight-path (RaySet) | A3 | `IdentityRay`/`LocatorRay`; per-vantage `Wavefront` | **Partial** | No generic Ray/RaySet feeding Parx. |
| Contact + Kontaktlücke residue | A2 | *Absent* (implicit in `focus()`) | **Absent** | No Contact object; missing contact not conserved. |
| Reflection + Boundary-Ambiguität residue | A9 | *Absent* | **Absent** | No seam-partner object/residue in observation layer. |
| Wavefront W (projection, not physical) | A4 (Regel 6.1) | `wavefront::Wavefront` (`wavefront.rs:21`); `asserts_physics=false` | **Realized** | Load-bearing invariant holds; constituents thinner than `Wave(Cells,Rays,Contacts,Parallax,Drift,X)`. |

### FiniteSymmetryKernel (L4 kernel)
| Theory element | Axioms | Codebase location | Verdict | Gap (short) |
|---|---|---|---|---|
| Csym=(G_n,S_n,Can,Stab,Spec,Φpan), n≤8 | — | `ssk-mpk::Graph`, `MAX_VERTICES=8` (`ssk-mpk/src/lib.rs:32`) | **Partial** | 5/6 members faithful; bound enforced; Φpan only Partial, no aggregate Csym type. |
| Orbit-Stabilizer \|Orb\|·\|Stab\|=n! | — | `orbit_size`/`automorphism_count`/`factorial` (`lib.rs:126,136,253`) | **Realized** | Proven by enumeration; `orbit_stabilizer_theorem` + proptest (400 graphs). |
| Canonicalization Can (lex-min, idempotent, iso-invariant) | A8 | `canon_key`/`canon` (`lib.rs:110,120`) | **Realized** | `canon_is_idempotent` + iso-invariance proptests. |
| Complement involution Comp²=id | — | `Graph::complement` (`lib.rs:147`) | **Realized** | `complement_is_an_involution` proptest (400 graphs). |
| Spec operator (exact spectrum) | — | `characteristic_polynomial` (`lib.rs:262`) | **Realized** | Newton's identities over exact i128; Schwenk pair test. |
| Kospektral Hold residue (Spec= ∧ G≇H ⟹ Hold) | A4,A5 | `CospectralGate::evaluate` (`lib.rs:381`) | **Partial** | A5 half enforced (Pass only on iso); A4 half missing — `Hold` carries no residue payload. |
| Multisignature Φpan = 5 channels | A4 | `MpkFieldSample` carries Φspec+ΦStab (`lib.rs:317`) | **Partial** | Only 2/5 channels; Φdeg/Φprops absent, Φtrace folded into Φspec; no `Φpan` type. |
| Kospektral-hold resolution ladder (D∈{deg,trace,Stab,props,catalog,boundary}) | A4,A5 | `CospectralGate::evaluate` + `Catalog::classify` (`lib.rs:381,420`) | **Partial** | canon collapses set into one iso test; lifted hold does not record which D; Hold terminal. |
| Content-addressed replay stability (I8) | A8 | `MpkFieldSample::of` + `MpkSampleId::of` (`lib.rs:340`) | **Realized** | `sample_is_replay_stable` + determinism proptest; digest commits beyond spectrum. |

### L5 Gate & Residue
| Theory element | Axioms | Codebase location | Verdict | Gap (short) |
|---|---|---|---|---|
| QState q=(s,φ,κ,r) + Stab(q) probe | A6 | `qlogic::QLogicInput` (`qlogic.rs:73`) | **Divergent** | Actual input is 8-field, no s/φ/r; `Stab(q)=d(q,Φ_U q)+d(q,Φ_V q)` entirely absent. |
| GateVector g=(κ,H,Π,R,B,Δ) axis semantics | A6 | `qlogic::{QAxis,QLogicVector}` (`qlogic.rs:19`) | **Divergent** | Only κ,H,Δ match. Π=parallax, R=replay, B=open-obligations — re-purposed. **Sensitive point.** |
| GateFamily G fail-closed conjunction | A6 | `QLogicVector::verdict`; `ssk-gates::GateVector::evaluate` (`ssk-gates/src/lib.rs:385`) | **Realized** | Worst-of, no early break, all non-pass residues kept. Missing: reject positive-only profiles. |
| Residue 5-tuple + taxonomy K (11 kinds) | A4 | `ssk-types::BoundaryResidue`, `ResidueKind` (`lib.rs:675,690`) | **Partial** | Fragment + NextAction absent, Status a bool; K missing Cospectral + FieldProjection. |
| ResidueCloud X (disjoint edge-partition + ρ*) | A4 | `ssk-types::ResidueRegister` flat Vec (`lib.rs:730`) | **Partial** | No edge-class partition (Def 11.6), no ρ* escalation (Inv 11.7). |
| CounterHorizon H: X→K×Status×NextAction | A4 | `ResidueRegister` (`lib.rs:730`) | **Partial** | Append-only in practice, not type-guaranteed; H triple incomplete (no Status/NextAction). |
| Blindspot 5-tuple + Vertrag 13.3 honesty | A4,A5 | `observer::Blindspot` (`observer.rs:60`) | **Partial** | Honesty enforced; Impact + RequiredAperture absent. |

### L6–L8 Closure / Atlas / Reanalysis
| Theory element | Axioms | Codebase location | Verdict | Gap (short) |
|---|---|---|---|---|
| FourPiClosure (2π≠4π, oriented double-return) | A7 | `closure::FourPiClosure::is_closed` (`closure.rs:59`) | **Partial** | Digest-equality of 2 passes only; no ℤ/2 sign, no `[S]_can` preservation, no Gegenhorizontmasse. |
| FourPi orientation-involutive; Clifford rotor C_4π | A7 | *Absent* (word "spinor" in doc-comment only) | **Absent** | No ℤ/2 carrier, no 2π sign-flip, no rotor. |
| Claim 8-tuple, Status∈{Pass,Hold,Fail} | A5 | `QOutcome` (Status only); `AtlasObservation` 5 fields (`atlas.rs:17`) | **Divergent** | No Claim 8-tuple; weight(c)=1 predicate inexpressible; append() unconditional. |
| Ledger Λ append-only, hash-chained | A5 | `atlas::append`/`verify_chain` (`atlas.rs:75,106`); `ssk-tensor::StitchTensor` | **Realized** | Tamper breaks chain; gate-failure preserves Λ. Λ realized as several parallel ledgers. |
| SelfPerceptionAtlas Φ (13-tuple) + ReanalysisState | A8 | `atlas::SelfPerceptionAtlas` (`atlas.rs:54`) | **Divergent** | The type **is** Ledger Λ, not Φ; no ClaimSet/ParallaxMatrix/ClosureReport/X/H/ReanalysisState. |
| ReanalysisOperator (verdict, class-idempotent, certifies S) | A8,A7 | `replay::reanalyze` (`replay.rs:139`) | **Partial** | Recovers class without writing 𝒮; returns booleans not `{Pass,ClassMismatch,Ambiguous}`; no idempotence, no [S+]. |
| Replay form ρ / RunDescriptor (deterministic) | A6,A8 | `ssk-replay::DeterministicReplayEngine::replay` (`lib.rs:40`) | **Realized** | Re-executes + diffs; manifest digests every committed input. |
| Wiederkehrstabilität w(Φ)=1 (3-conjunct) | A8 | *Absent* (three conjuncts exist independently) | **Absent** | No certificate conjoins replay ∧ reanalysis ∧ anchor-invariance. |
| Drift-Hysterese DM∈{Komp,Neu}, θ_on>θ_off | A8 | `qlogic.rs:215` Δ single bound; `ssk-meta-resonance::step` (`lib.rs:97`) | **Divergent** | Single-threshold point predicate — the exact form Satz 16.9 proves wrong; no bistable band. |
| Run-transition reset 𝜚 + version ratchet ℓ | A8 | *Absent* | **Absent** | No monotone stage counter, no reset, no [S]→[S+], no evidence-asymmetry. |

### L9 Boundary / CompatibilityShell
| Theory element | Axioms | Codebase location | Verdict | Gap (short) |
|---|---|---|---|---|
| BoundaryInterface B: Φ×Shell→FIT | A9,A10 | *Absent* | **Absent** | No `B(Φ,Shell)→Fit`; Atlas has no fit surface. |
| CompatibilityShell (8-tuple boundary surface) | A10 | `ssk-interop::CompatibilityPolicy` (`lib.rs:482`) | **Divergent** | The only "Compatibility" type is a wire-handshake negotiator; 8 boundary components absent. |
| A9 Anschlussdisziplin (crossing=closure object) | A9 | `ssk-bcik::Bcik::cross` (`lib.rs:65`); `CrossOutcome` (`ssk-types:606`) | **Partial** | No-silent-crossing type-enforced at crossing level; closure from boolean flags; not lifted to Atlas. |
| A10 Semantische Nichtvermischung (5 translation objects) | A10 | `SeamWitness`, `BoundaryRecord`, `ResidueKind::Boundary` | **Partial** | 2/5 objects; GateMap/ReplayBridge/ResidueLift absent; objects lack Trace+Replay; no B ledger. |
| Identity/Locator split non-convertible | A1 | `CoreNode`/`MirrorFacet` vs `LocatorFacet` (`ssk-types:205,347`) | **Realized** | Holds by construction (no From/Into); add trybuild guard. |
| Ω border 1 — CoreNode / IdentityPlane | A1,A9 | `ssk-types::CoreNode` (`lib.rs:205`); `ssk-identity::derive_identity_facet` | **Realized** | Canonical self-node, distinct from LocatorFacet; recover round-trip. |
| Ω border 2 — LocatorPlane | A1,A9 | `ssk-types::LocatorFacet` (`lib.rs:347`); `ssk-locator::StaticLocatorPool` | **Realized** | Closed 9-variant egress taxonomy; carries no identity/CoreId field. |
| Ω border 3 — BCIK-SeamCrossing | A9 | `ssk-bcik::Bcik::cross`; `CrossOutcome`/`SeamWitness`/`BoundaryRecord` | **Realized** | No silent-success variant. Limitation: closure gated on boolean flags (Phase-2 placeholders). |
| Ω border 4 — Twelve-Gate-Vector | A6,A9 | `GateId::ALL` (`ssk-types:653`); `ssk-gates::GateVector::with_all_default` | **Realized** | 12 gates, closed set, fail-closed. Naming: Hypercube≡PCH alias to document. |
| Ω border 5 — RunDescriptor / Replay | A8,A9 | `ssk-types::RunDescriptor` (`lib.rs:890`); `DeterministicReplayEngine` | **Realized** | Complete determinism inputs; bit-exact replay verdict. |
| Ω border 6 — ResidueRegister / ResidueBoundary | A4,A9 | `ssk-types::ResidueRegister` (`lib.rs:731`), `ResidueKind` (9) | **Realized** | Append-only, closed 9-kind taxonomy, no removal API. |
| Ω border 7 — Persistent Stitch Tensor | A9,A10 | `ssk-tensor::StitchTensor` (`lib.rs:174`), `apply_sorted` gate-passed-only | **Partial** | Stitch-level invariant realized; no Atlas→Stitch path (theory's own open residue ρ03/Res. 18.2). |
| Ω border 8 — Concave Reanalysis Focus | A8,A7 | `ssk-focus::FocusEngine::reanalyze` (`lib.rs:85`) | **Realized** | Honest `Pass/ClassMismatch/Ambiguous`; conservative reconstruction (disclosed). |
| AuditBoundary component (append-only, hash-chained) | A5,A9 | `SelfPerceptionAtlas` (`atlas.rs:55`); `ssk-boundary::BoundaryAuditEntry` (`lib.rs:166`) | **Realized** | Tamper-evident at arbitrary depth; several per-crate ledgers, none designated THE shell slot. |

---

## 5. Ranked Gap List

Every Partial/Divergent/Absent row → a numbered implementation item. **Ranked by axiom-criticality
(A1/A4/A6/A7 highest) then verdict severity (Absent/Divergent before Partial) then blast radius.**

### 5a. Resolution Log (implementation pass 1)

The following gaps have been **closed** in this pass — each with a proof-obligation test, verified against a
green workspace (build + fmt + clippy `-D warnings` + full test suite). Gaps not listed remain open per §5b.
This log is authoritative over the per-tier "verdict" lines below where they disagree; the tier text is kept
as the original problem statement.

| Gap | Axiom | Status | Crate | Discharging test(s) |
|---|---|---|---|---|
| **G1** NullAnchor Z (L0 fixpoint) | A1 | ✅ Realized | `ssk-imdf::self_anchor` | `null_anchor_commitment_is_deterministic_and_domain_separated`, `null_anchor_orders_the_self_anchor_without_emitting_z`, `same_null_anchor_binds_anchors_to_the_same_recovery_root` (structural: `NullAnchor` derives no `Serialize`) |
| **G2** Anchor-Stability drift-fork | A1,A8 | ✅ Realized | `ssk-imdf::replay` | `drift_past_bound_forks_a_new_run_without_mutating_the_old` |
| **G3** GateVector six-axis semantics (Π/R/B) | A6 | ✅ Realized (re-map, not §3.2 divergence) | `ssk-imdf::qlogic`, `ssk-system` | `each_axis_binds_to_its_theory_quantity`, `non_finite_projection_and_residue_fail_closed`, `parallax_and_replay_evidence_genuinely_gate_the_pipeline` |
| **G4** QState q=(s,φ,κ,r) + Stab(q) probe | A6 | ✅ Realized | `ssk-imdf::qlogic` | `qstate_stab_confers_relevance_only_under_nonvanishing_parallax` |
| **G5** FourPi ℤ/2 orientation rotor | A7 | ✅ Realized | `ssk-imdf::closure` | `orientation_is_zz2_graded` |
| **G6** FourPiClosure 2nd conjunct + Gegenhorizontmasse | A7 | ✅ Realized | `ssk-imdf::closure` | `four_pi_requires_second_orientation_pass`, `drifted_self_class_yields_gegenhorizontmasse_not_closure`, `inconsistent_second_pass_does_not_close` |
| **G7** HostAuthority residue | A4 | ✅ Realized | `ssk-host-cells` | `under_capability_denial_conserves_a_host_authority_residue` |
| **G8** ResidueCloud X edge-partition + ρ* | A4 | ✅ Realized | `ssk-types` | `residue_cloud_partitions_disjointly_with_rho_star_catch_all` |
| **G9** Residue 5-tuple + taxonomy K (11 kinds) | A4 | ✅ Realized | `ssk-types` | `residue_is_the_complete_five_tuple_over_taxonomy_k` |
| **G10** CounterHorizon H register triple | A4 | ✅ Realized | `ssk-types` | `counter_horizon_register_is_append_only_and_h_is_total` |
| **G11** Kospektral Hold residue payload | A4,A5 | ✅ Realized | `ssk-mpk` | `cospectral_hold_carries_a_conserved_residue_payload` |
| **G12** Kospektral-hold resolution ladder | A4,A5 | ✅ Realized | `ssk-mpk` | `cospectral_hold_is_lifted_by_the_first_separating_distinguisher` |
| **G16** Run-transition reset ϱ + ratchet ℓ | A8 | ✅ Realized | `ssk-meta-resonance` | `version_ratchet_reset_is_idempotent_monotone_and_asymmetric` |
| **G15** Drift-Hysterese double-threshold | A8 | ✅ Realized | `ssk-meta-resonance` | `drift_mode_is_bistable_in_the_band`, `drift_mode_flips_only_at_thresholds` |
| **G17** Wiederkehrstabilität w(Φ)=1 | A8 | ✅ Realized | `ssk-imdf::replay` | `stability_certificate_is_the_conjunction_of_three_conjuncts` |
| **G18** ReanalysisOperator verdict/idempotence | A8,A7 | ✅ Realized | `ssk-imdf::replay` | `reanalysis_verdict_is_typed_and_class_idempotent` |
| **G24** Claim 8-tuple + weight-gating | A5 | ✅ Realized | `ssk-imdf::claim` | `well_formed_claim_has_weight_one_and_is_written`, `groundless_claim_is_entwurf_and_refused`, `gate_undefined_claim_is_hypothese_and_refused`, `undeclared_residue_claim_is_refused` |
| **G25** ObserverField aggregate + k-way parallax | A5,A3 | ✅ Realized | `ssk-imdf::observer_field` | `observer_field_enumerates_distinct_observers_and_takes_k_way_parallax`, `observer_field_rejects_duplicate_observers` |
| **G26/G27** Blindspot 5-tuple + actionable residue | A4,A5 | ✅ Realized | `ssk-imdf::observer` | `blindspot_is_the_full_five_tuple`, `blindspot_residue_drives_required_aperture_remediation` |
| **G28** ParallaxOperator pseudometric | A3 | ✅ Realized | `ssk-imdf::wavefront` | `parallax_divergence_is_symmetric_and_zero_on_self` |
| **G29** SplitOperator role-orthogonality | A3 | ✅ Realized | `ssk-imdf::wavefront` | `birefringent_split_of_a_copy_is_not_orthogonal`, `a3_obligation_binds_only_to_orthogonal_splits` |
| **G30** SplitAxis enum | A3 | ✅ Realized | `ssk-imdf::wavefront` | `every_split_declares_its_axis` |
| **G31** Ray / RaySet | A3 | ✅ Realized | `ssk-imdf::wavefront` | `split_yields_a_ray_set_of_at_least_two_orthogonal_rays` |
| **G34** Contact + Kontaktlücke residue | A2 | ✅ Realized | `ssk-imdf::contact` | `uncontacted_emphasis_becomes_a_conserved_kontaktluecke`, `blindspot_emphasis_is_a_deferred_not_blocking_gap` |
| **G36** Aperture algebra proofs | A2 | ✅ Realized | `ssk-imdf::aperture` | `focus_is_idempotent_on_the_same_surface`, `focus_partitions_every_surface_dimension_without_loss` |

**Still open after this pass (see §5b tiers):** G13 (Multisignature Φpan), G14 (Atlas Φ 13-tuple),
G19–G23 (Boundary interface B, CompatibilityShell, GateMap/ReplayBridge/ResidueLift, Atlas materialization),
G32/G33/G35/G37 (ImmersionField, FieldCell fold, Lens-as-operator, MirrorDome façade), G38 (Reflection +
Boundary-Ambiguität), G39 (Csym aggregate). Most of these are the A9/A10 boundary layer (the ρ02/ρ03 open
residues bound what a total realization can be) plus the L2/L4 aggregate façades. The §7 open residues
(ρ01–ρ18) remain theory-designated non-gaps.

### 5b. Original ranked gap list

### Tier 1 — A1 (SelfAnchor-priority: foundation)
**G1. NullAnchor Z (L0 fixpoint) — Absent [A1].**
Task: introduce a `NullAnchor` type in `ssk-types`/`ssk-imdf` holding `(order_ref, recovery_root)` with no
public constructor placing it in `LocatorPlane`/`PublicSurface`, no `Serialize` path over a boundary, and a
sealed `orders(Z,S)` relation; wire SelfAnchor construction/recovery to reference it.
*Proof obligation:* trybuild compile-fail proving `NullAnchor` has no `From`/`Into` into any Locator/PublicSurface
type and does not derive `Serialize`, plus a unit test asserting absence from every serialized boundary payload
(the L0 analogue of `self_anchor_is_not_locator`).

**G2. Anchor-Stability drift-fork (Vertrag 8.3) — Divergent [A1,A8].**
Task: add `RunId` + `prior_trace` to `RunDescriptor`; when measured drift exceeds `drift_bound`, close the current
run and open a new one whose descriptor back-references the superseded trace digest; forbid in-place mutation via
the append-only atlas.
*Proof obligation:* property test — drift>bound yields a distinct `RunId`, new `prior_trace` == old committed trace
digest, old descriptor byte-unchanged (anchor-drift analogue of `audit_ledger_is_append_only`).

### Tier 2 — A6 (Gate multidimensionality: the sensitive divergence)
**G3. GateVector six-axis semantics — Divergent [A6]. (HEADLINE)**
Task: re-map Π←projection-quality, R←residue-load `λ=|X(c)|/|M(c)|` (Def 12.5), B←boundary-stability; move the
parallax check to an A3 site and replay-equality to a separate replay obligation — OR register the re-mapping as
an explicit, versioned §3.2 Fortschreibung.
*Proof obligation:* per-axis binding enumeration test asserting each symbol reads its theory quantity. The existing
`gate_vector_is_not_single_score` PASSES under the divergent mapping — it does **not** pin axis semantics.

**G4. QState q=(s,φ,κ,r) + Stab(q) probe — Divergent [A6].**
Task: introduce a `QState` = (band s, phase φ, coherence κ, residue-mark r) as the gate's typed input; compute
`Stab(q)=d(q,Φ_U q)+d(q,Φ_V q)` from two orthogonal kicks; make gate-relevance depend on non-vanishing parallax
(Inv 9.6).
*Proof obligation:* property test — `QState` round-trips all four components and `Stab(q)` only confers relevance
under controlled non-vanishing parallax. No such test exists.

### Tier 3 — A7 (4π-closure)
**G5. FourPi ℤ/2 orientation / Clifford rotor — Absent [A7].**
Task: introduce a `Cl(p,q)` even-subalgebra rotor `R(φ)=cos(φ/2)−sin(φ/2)B̂` (or minimally a ℤ/2 orientation
accumulator); represent orientation by `ψ↦Rψ` vs surface conjugation `v↦Rv~R`; drive closure off it.
*Proof obligation:* kernel-style enumeration — trajectory closes exactly at 4π; `R(2π)ψ=−ψ ∧ R(4π)ψ=+ψ`; `R(4π)=+1`.

**G6. FourPiClosure second conjunct + Gegenhorizontmasse — Partial [A7].**
Task: bind `OrientationPass` to a ℤ/2 grade relative to the SelfAnchor; make `is_closed` require BOTH orientation
return AND `[S]_can` preserved; on the second-conjunct failure emit a 𝒳_FourPi (Gegenhorizontmasse) residue
instead of a bare `Open`.
*Proof obligation:* property test discharging both Satz 12.4 conjuncts. Existing `four_pi_requires_second_orientation_pass`
covers only the pass-count conjunct.

### Tier 4 — A4 (Residue conservation / No Silent Loss)
**G7. HostAuthority residue — Absent [A4].**
Task: have `HostCellPlane::can`/`act` emit a HostAuthority residue on every capability/scope denial.
*Proof obligation:* property that every denial produces exactly one HostAuthority residue entry.

**G8. ResidueCloud X disjoint edge-partition + ρ* — Partial [A4].**
Task: type each residue's origin as a closed edge-class enum; enforce a total disjoint partition of X; escalate any
residue lacking an origin edge to a meta-residue ρ*.
*Proof obligation:* partition property test — union of edge-classes == X, pairwise disjoint, origin-less → ρ*.
Today only run-level `no_silent_loss` exists — it does not prove the partition.

**G9. Residue 5-tuple + taxonomy K (11 kinds) — Partial [A4].**
Task: extend `BoundaryResidue` with `fragment` and `next_action` and a 3-valued status; add `Cospectral` and
`FieldProjection` to `ResidueKind` to close K.
*Proof obligation:* struct-shape test that every emitted residue exposes all five fields populated;
taxonomy-closure test enumerating all 11 kinds and forbidding a silent "other".

**G10. CounterHorizon H register triple — Partial [A4].**
Task: make `ResidueRegister` strictly append-only at the type level (no interior mutation/removal); add per-entry
Status and NextAction so `H(r)` yields the full `(class, status, next_action)` triple.
*Proof obligation:* append-only property (emit monotone, length never decreases, no removal API) + H completeness test.

**G11. Kospektral Hold residue payload — Partial [A4,A5].**
Task: make the cospectral outcome carry a residue object (held candidate keys + reason "spectrum insufficient")
rather than a bare `GateOutcomeKind::Hold`.
*Proof obligation:* the `Hold` value exposes a non-empty content-addressed residue recording ≥2 held candidates.
`cospectral_non_isomorphic_holds_never_passes` discharges only the A5 half.

**G12. Kospektral-hold resolution ladder — Partial [A4,A5].**
Task: add `resolve_hold(G,H)` trying the six distinguishers in theory order, returning the first `D(G)≠D(H)` and
recording it in the Hold residue; wire Catalog + a BoundaryInterface distinguisher.
*Proof obligation:* enumeration over all cospectral non-isomorphic pairs on n≤7 — each lifted by a named D that
genuinely separates; unresolvable pairs stay Hold. `out_of_catalog_holds` discharges the catalog rung.

**G13. Multisignature Φpan channels — Partial [A4].**
Task: add `DegreeSignature`, `TracePowerSignature`, `PropertySignature`, then a `PanSignature=(spec,deg,stab,trace,props)`
with a documented ⊕ ordering; make `MpkFieldSample` carry it.
*Proof obligation:* Φpan relabeling-invariant on all n≤6; separates the Schwenk pair via deg/props;
`Φpan(G)=Φpan(H) ⟹` enumerated-isomorphism for the n≤6 catalog.

### Tier 5 — A8 (Reanalysis-binding & Atlas)
**G14. SelfPerceptionAtlas Φ 13-tuple — Divergent [A8].**
Task: model Φ as the 13-tuple aggregating existing subsystems (observers, aperture map, FourPiClosure report,
residue register X/H, reanalysis report), keeping the hash-chain as Λ separately; carry a `ReanalysisState` field.
*Proof obligation:* Satz 15.4 — a Φ with empty `ReanalysisState` fails `AtlasCrystallized`/`ReanalysisBound`.

**G15. Drift-Hysterese single-threshold — Divergent [A8].**
Task: add a `DriftMode` state machine carrying θ_on/θ_off and a persisted mode; drive the compensate-vs-new-run
decision off DM, not a point threshold.
*Proof obligation:* Satz 16.9 bistability — for Δ∈(θ_off,θ_on), approach-from-below yields Komp and
approach-from-above yields Neu at the same Δ.

**G16. Run-transition reset 𝜚 + version ratchet ℓ — Absent [A8].**
Task: read a monotone stage ℓ off the append-only ledger; implement 𝜚 as an idempotent max-projection triggered at
the Komp→Neu transition; enforce non-falling ℓ + half-weight preloading for future marks.
*Proof obligation:* idempotence `𝜚∘𝜚=𝜚` (Satz 16.12), ratchet `ℓ_{k+1}≥ℓ_k` (Satz 16.13), past-vs-future asymmetry (Inv 16.15).

**G17. Wiederkehrstabilität w(Φ)=1 certificate — Absent [A8].**
Task: add a stability certificate conjoining the replay verdict (Deterministic), a reanalysis Pass, and an
anchor-invariance check; fork a new run on anchor drift.
*Proof obligation:* `w(Φ)=1` iff all three conjuncts hold, `=0` if any single one fails.

**G18. ReanalysisOperator verdict/idempotence — Partial [A8,A7].**
Task: return a typed `{Pass,ClassMismatch,Ambiguous}` verdict; add the versioned-successor `[S']→[S+]` branch; fold
in a focus-path replay check; expose an idempotence guarantee.
*Proof obligation:* class-idempotence `[Reanalyse(Reanalyse(Φ,ℰ),ℰ)]_can=[Reanalyse(Φ,ℰ)]_can`.
`reanalysis_recovers_self_anchor` covers only single-shot recovery.

### Tier 6 — A9 / A10 (Boundary discipline & non-mixing)
**G19. BoundaryInterface B(Φ,Shell)→Fit — Absent [A9,A10].**
Task: add an `ssk-boundary-interface` crate defining `InterfaceFit` and a pure
`boundary_fit(atlas, shell) -> InterfaceFit` conjuncting eight compatibility predicates, borrowing (never mutating) both.
*Proof obligation:* `boundary_fit` is total, leaves Φ and Shell byte-identical, returns Fit iff all eight predicates
hold (enumerate the 2^8 table or each single-false case → non-Fit). Mirrors Satz 18.4.

**G20. CompatibilityShell 8-tuple — Divergent [A10].**
Task: introduce a `CompatibilityShell` with the eight named boundary components, each a predicate over the relevant
border object; keep `ssk-interop::CompatibilityPolicy` as the distinct wire-handshake concept (rename to avoid the
Ω-term collision, Regel 17.4).
*Proof obligation:* enumeration test — shell has exactly the eight Def 18.1 components mapping to their Ω-image
(Tab. 10); golden test asserting `CompatibilityPolicy` is NOT presented as the shell (semantic-non-mixing guard).

**G21. Persistent Stitch Tensor Atlas-materialization — Partial [A9,A10].**
Task: once B exists, add an Atlas→Stitch materialization that fires only after `B(Φ,Shell)=Fit` AND Ω-side gate
passage, resolving tensor-granularity residuum 18.2.
*Proof obligation:* test that an Atlas cannot materialize a tensor entry unless it passed the full CompatibilityShell
passage (currently untestable — B absent). Stitch-level invariant already discharged.

**G22. A9 Anschlussdisziplin lift to Atlas — Partial [A9].**
Task: thread real per-fiber invariant checking into `Bcik::cross` (replace boolean candidate flags); lift the
closure-or-residue discipline to the Atlas→Ω docking path once B exists.
*Proof obligation:* property test that `cross` NEVER returns without either a SeamWitness-bearing stitch or a
register-emitted residue. `cross_returns_residue_when_open` + `cross_returns_a_closed_stitch...` discharge crossing-level.

**G23. A10 GateMap / ReplayBridge / ResidueLift — Partial [A10].**
Task: add these three Trace+Replay-bearing boundary objects in the B crate, each appending to a boundary ledger;
represent every incomplete translation as a `ResidueKind::Boundary` entry with `open_obligation=true`.
*Proof obligation:* test that every boundary-translation object carries a Trace and ReplayRef; an incomplete GateMap
(IMRT gate with no Ω image) yields a visible boundary residue, not a silent map.

### Tier 7 — A5 (Claim-gating)
**G24. Claim 8-tuple — Divergent [A5].**
Task: add a `Claim` struct with all eight fields; gate materialization/append on `weight(c)=1`; classify Ground=∅ as
Entwurf and Gate-undefined as Hypothese and refuse to append them to Λ.
*Proof obligation:* Satz 14.5 — a claim missing Ground or Residue has weight 0 and is not written; a fully-formed one is.

**G25. ObserverField aggregate — Partial [A5,A3].**
Task: introduce `ObserverField(Vec<ObserverModel>)` with a distinctness invariant and k-way parallax feeding the
atlas ObserverManifold.
*Proof obligation:* property that the ObserverManifold enumerates every observer and each gate-relevant claim's
parallax is over ≥2 members.

**G26. Blindspot 5-tuple — Partial [A4,A5].**
Task: extend `Blindspot` with `impact` and `required_aperture`, split `missing_instrument` from `surface`, carry the
observer id explicitly.
*Proof obligation:* `blindspot_is_not_reported_as_fact` discharges Vertrag 13.3; add a shape test asserting all five
fields present and non-empty.

**G27. Blindspot residue actionable — Partial [A5,A4].**
Task: extend the observer-side `Blindspot` with `missing_instrument`, `impact`, `required_aperture` so the residue can
drive a required-aperture remediation.
*Proof obligation:* property that every `Blindspot` names a `RequiredAperture`. (Overlaps G26; may be merged.)

### Tier 8 — A3 (Parallax obligation)
**G28. ParallaxOperator pseudometric — Partial [A3].**
Task: realize `Parx` as `global_distance(Lens r_i, Lens r_j)`; add pseudometric property tests; require ≥2 distinct
rays for gate relevance; separate the Π=projection-quality gate axis from parallax.
*Proof obligation:* symmetry, `Parx(r,r)=0`, triangle inequality; `split_parallax_detects_inconsistent_views` for the
disagreement direction.

**G29. SplitOperator role-orthogonality / m≥2 — Partial [A3].**
Task: enforce role-orthogonality on `BirefringentSplit` (reject identical wavefronts / require distinct vantages) and
generalize to m≥2.
*Proof obligation:* property that `BirefringentSplit` rejects a copy (left==right); `birefract_splits_into_an_identity_ray_and_a_locator_ray`
covers the typed-orthogonal case.

**G30. SplitAxis enum — Partial [A3].**
Task: introduce a `SplitAxis` enum, tag every Split with its axis, realize the remaining axes.
*Proof obligation:* enumeration test that every constructed Split carries a declared `SplitAxis` from the admissible set.

**G31. Ray / RaySet — Partial [A3].**
Task: unify per-vantage observation as a `Ray`/`RaySet` feeding the parallax operator.
*Proof obligation:* structural test that each Split yields a RaySet of ≥2 rays consumed by Parx.

### Tier 9 — A2 (Aperture-before-focus apparatus)
**G32. ImmersionField IF + Immerse — Absent [A2].**
Task: define an `ImmersionField` aggregating the L4 constituents anchored to a `SelfAnchor`, plus an `Immerse` operator.
*Proof obligation:* property that Immerse is total and injective on the SelfAnchor space; structural test that IF holds
S, Cells, Rays, Contacts, Reflections, X, Trace.

**G33. FieldCell fold — Divergent [A2].**
Task: define a `FieldCell` folding the role-cell binding with observation state (pos/phase/coherence/features/residue/trace).
*Proof obligation:* structural test that a FieldCell carries BOTH a capability/scope binding AND phase/coherence/residue/trace.

**G34. Contact + Kontaktlücke residue — Absent [A2].**
Task: model a `Contact` object and emit a Kontaktlücke residue when an admitted surface has no contact.
*Proof obligation:* test that an admitted-but-uncontacted surface yields a Kontaktlücke residue.

**G35. Lens as operator — Partial [A2,A4].**
Task: make `Lens` the operator (`Lens::focus(apertured)->(Body,Res)`) or fold its role into `focus()` and delete the
inert type.
*Proof obligation:* `Apt_i(Raw)=π_Body ⊔ π_Res` (disjoint + exhaustive); partly discharged by `hidden_surface_becomes_residue`.

**G36. Aperture algebra proofs — Partial [A2].**
Task: add a proptest that `focus∘focus = focus` and that readings-keys ⊆ signature dimensions.
*Proof obligation:* property test `Apt(Apt(Y))=Apt(Y) ∧ Apt(Y)⊆Y` over arbitrary `SpectralSignature`s.

**G37. MirrorDome façade + self-before-foreign — Partial [A2,A3].**
Task: add a MirrorDome façade composing the L1→L7 chain in one place and encoding the self-before-foreign ordering.
*Proof obligation:* end-to-end test driving S through Immerse→Cells/Rays→Split→Parallax→Wavefront→Gate→Atlas,
asserting every stage is exercised and a self-vantage observation is required before any foreign-vantage contributes to Φ.

### Tier 10 — A9 observation object & kernel aggregate
**G38. Reflection + Boundary-Ambiguität residue — Absent [A9].**
Task: model `Reflection` (seam-partner) with a Boundary-Ambiguität residue on unresolved reflections.
*Proof obligation:* test that an ambiguous seam yields a Boundary-Ambiguität residue.

**G39. FiniteSymmetryKernel Csym aggregate — Partial [—].**
Task: complete the Φpan channel (G13) so all six declared members exist; optionally introduce a named `Csym` apparatus
type bundling `(G_n,S_n,Can,Stab,Spec,Φpan)`.
*Proof obligation:* enumeration over n=2..=8 confirming every Graph builds and every operator terminates
(`n>MAX_VERTICES` rejection already verified). Full Realized additionally requires the Φpan obligation (G13).

---

## 6. Proof-Obligation Register (per axiom)

For each axiom: the property/test that discharges it. **Existing** tests are named where they already discharge;
the rest are **to-build**.

| Axiom | Discharging property | Existing test(s) | To-build |
|---|---|---|---|
| **A1** | Identity id ≠ locator id from same source; no From/Into either way; L0 fixpoint never emitted | `self_anchor_is_not_locator` (`self_anchor.rs:183`); `anchor_id_is_deterministic_and_field_sensitive` | trybuild compile-fail `LocatorRay::from(identity)` / `SelfAnchor` non-convertibility (G1, G29 guards); NullAnchor never-serialized test (G1) |
| **A2** | Focus unreachable from closed aperture; Dump conserved; `Apt∘Apt=Apt ⊆` | `aperture_before_focus_required` (`observer.rs:235`); `hidden_surface_becomes_residue` (`observer.rs:249`) | aperture idempotence/contraction proptest (G36); Immerse total+injective (G32) |
| **A3** | Parallax pseudometric axioms; ≥2 distinct rays for gate relevance; split rejects copy | `split_parallax_detects_inconsistent_views` (`wavefront.rs:163`); `birefract_splits_into_an_identity_ray_and_a_locator_ray` | symmetry/`Parx(r,r)=0`/triangle (G28); copy-rejection (G29); SplitAxis enumeration (G30) |
| **A4** | Every non-integrated part → exactly one edge-class or ρ*; residue 5-tuple complete; taxonomy K closed | `no_silent_loss` (`ssk-runtime/tests/conformance.rs:77`); `residue_visibility_completeness_...` (`ssk-privacy/src/lib.rs:208`) | X partition + ρ* (G8); 5-field + 11-kind K (G9); H triple (G10); HostAuthority/Kontaktlücke residues (G7, G34) |
| **A5** | Unauthorized observer inconstructible; blind never a fact; claim weight-gated | `observer_without_authorization_fails` (`observer.rs:216`); `blindspot_is_not_reported_as_fact` (`observer.rs:270`) | Claim weight(c)=1 gating (G24); ObserverField k-way parallax (G25) |
| **A6** | Fail-closed conjunction; per-axis semantics bound to theory quantity | `gate_vector_fail_closed` (`ssk-gates/src/lib.rs:518`); `all_twelve_gates_are_evaluated_even_after_an_early_reject` (`:688`); `gate_vector_is_not_single_score` (`qlogic.rs:252`) | per-axis binding enumeration Π/R/B (G3); QState 4-tuple + Stab(q) (G4); reject positive-only profiles |
| **A7** | Closes exactly at 4π; `R(2π)ψ=−ψ`, `R(4π)ψ=+ψ`; `[S]_can` preserved else Gegenhorizontmasse | `four_pi_requires_second_orientation_pass` (`closure.rs:96`) | rotor sign-flip enumeration (G5); both Satz 12.4 conjuncts + residue (G6) |
| **A8** | Replay bit-exact; reanalysis class-idempotent; ratchet monotone; w(Φ) conjunction | `genuinely_re_executed_run_matches_its_own_manifest` (`ssk-replay:111`); `reanalysis_recovers_self_anchor` (`replay.rs:211`); `sample_is_replay_stable` (`ssk-mpk:522`) | class-idempotence (G18); ratchet+reset (G16); drift bistability (G15); w(Φ) certificate (G17); drift-fork (G2) |
| **A9** | Every crossing → Seam ∧ Boundary ∧ (Closure ∨ Residue); B total & non-mutating | `cross_returns_residue_when_open` (`ssk-bcik:183`); `cross_returns_a_closed_stitch...` (`:192`); `mid_chain_tamper_is_always_caught` (`ssk-boundary:623`) | B(Φ,Shell) totality + 2^8 conjunct table (G19); Atlas-level lift (G22) |
| **A10** | No Ω term in core; translations only at B, logged; unfinished → visible residue | *(none — translation objects mostly absent)* | 8-component shell enumeration + non-mixing golden test (G20); GateMap/ReplayBridge/ResidueLift Trace+Replay (G23) |

**Kernel (no-axiom, but load-bearing) — already fully discharged:** `orbit_stabilizer_theorem` +
`orbit_stabilizer_holds_for_all_graphs`, `canon_is_idempotent` + `canon_is_invariant_under_relabeling`,
`complement_is_an_involution`, `cospectral_non_isomorphic_holds_never_passes`, `sample_is_deterministic_for_all_graphs`.

---

## 7. Open Residues (deliberately not realizable now)

Applying the theory's own **No-Silent-Loss discipline (§20, Axiom 10.4 reflexively)** to *this specification*: the
following are theory-designated residues (classes R / F / B in Def 20.1), NOT closable implementation gaps. They are
inherited, not solved — recorded here so nothing slips into the blind spot.

| ID | Residue | Class | Bearing on this spec |
|---|---|---|---|
| ρ01 | Ideal null-residue Atlas (μ=1, λ=0): definable, never guaranteed reachable | R (open, upper bound) | A perfect `ResidueConserved`/`CounterHorizonMapped` is an asymptote; the register targets *visibility*, not emptiness. Do not treat non-empty X as a defect. |
| ρ02 | Gate-image gap: Π, Δ map ambiguously onto Ω-gates | B (boundary) | Bounds G23 (GateMap): a total IMRT→Ω gate injection may be impossible; unmapped gates must surface as boundary residues, not be forced. |
| ρ03 | Tensor granularity: one Atlas → many stitches, not canonical | B (boundary) | This is exactly the open half of G21 (Ω border 7). The Atlas→Stitch materialization rule is a boundary decision, deliberately deferred (Res. 18.2). |
| ρ04 | Symmetry-kernel distinguisher export beyond the boundary is open | B/F | Bounds G12/G13: the resolution ladder and Φpan channels are realizable *inside* the kernel; their Ω-export is a boundary/research question. |
| ρ05 | Parallax metric choice: `d` fixed only as a pseudometric, not concretized | F (model choice) | G28 must realize *a* pseudometric satisfying the axioms; the *specific* `d` (e.g. `global_distance`) is a model choice, not theory-mandated. |
| ρ06 / ρ16 | Gate-component thresholds (κ,H,Π,R,B,Δ) and θ_on/θ_off are Policy, not Theory quantities | D/F (delegated) | G3/G15 fix the *semantics and form*; the numeric thresholds are policy and stay out of the invariant. |
| ρ07 | Model class n≤8 of the symmetry kernel is declared, not theoretically forced | D (fixed by declaration) | The `MAX_VERTICES=8` bound is correct-as-declared; G39 need not "prove" n≤8, only enforce it (already done). |
| ρ08 | Successor relation [S]→[S+]: ratchet-monotonicity necessary (N1), sufficient criterion open | F (partly defused, Satz 16.13) | G16 can implement the *necessary* ratchet; the *sufficient* successor criterion remains an open research question. |
| ρ11 / ρ15 / ρ17 | Drift double-threshold+mode (solved N1); Clifford-rotor realization (N1); signature (p,q) open | D/O / F | G15 and G5 realize the N1-upgraded structures; the Clifford signature (p,q) is itself declared open — pick minimally (a ℤ/2 accumulator suffices). |
| ρ12 | Evidence space ℰ set as reanalysis input, internally undefined (blackbox) | D (set) | G18's reanalysis takes ℰ as an opaque input; do not over-specify its internals. |
| ρ13 | Meta-residue ρ*: residues without an origin edge = critical error, kept as a catch-all | R (catch-all) | G8 must implement ρ* as the closure-guaranteeing catch-all, not eliminate it. |
| ρ18 | Kernel verification status: empirical corroboration, not machine-checked proof | D (declared) | The kernel proof obligations in §6 are corroboration-grade; a machine-checked proof is explicitly out of scope. |

---

## 8. Next: Implementation Sequencing (deferred to follow-up)

Implementation is **explicitly deferred to a follow-up pass.** Recommended order to close gaps, chosen so that
foundational objects other gaps depend on land first:

1. **Foundation first (unblocks everything):** G1 (NullAnchor Z) then G2 (anchor-drift fork). Without an L0
   fixpoint and a drift→new-run rule, `SelfAnchored`/`NullReferenced`/`ReanalysisBound` cannot be closed.
2. **The headline A6 divergence:** G3 (re-map Π/R/B or register the Fortschreibung) and G4 (QState). This is the
   single most consequential honesty item — the gate currently qualifies against the wrong quantities. Decide
   *explicitly* between re-mapping to theory semantics vs. a versioned §3.2 amendment.
3. **A4 residue spine:** G9 (5-tuple + K closure) → G8 (X partition + ρ*) → G10 (H triple), then the point
   residues G7/G34/G11. These share the `ResidueRegister`/`BoundaryResidue` types, so do them as one sweep.
4. **A7 closure:** G5 (ℤ/2 rotor) then G6 (second conjunct + Gegenhorizontmasse) — G6 depends on G5's carrier.
5. **A8 atlas & stability:** G14 (Φ 13-tuple) is the aggregation others hang off; then G18/G17/G15/G16.
6. **A9/A10 boundary:** G19 (B) and G20 (Shell) are prerequisites for G21/G22/G23 — the border *objects* are
   already Realized, so this is mostly the missing certifier + shell + translation objects.
7. **Observation apparatus & parallax (A2/A3):** G28–G37 — lower blast radius, largely local to `ssk-imdf`.

The 24 Realized rows (notably the entire FiniteSymmetryKernel, the 12-gate fail-closed vector, append-only
hash-chained ledgers, deterministic replay, and the identity/locator non-convertibility) are the solid substrate
this sequencing builds on and should be **guarded with the trybuild compile-fail tests noted above** so future
edits cannot silently regress them.
