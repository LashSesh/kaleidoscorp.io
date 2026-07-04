# FCHL-MPK ↔ SSK Integration Strategy

**Normative source:** `FCHL-MPK Architektur-Addendum` (Produktions-Master-Spezifikation, Normative Integrationsfassung 1.0, Sebastian Klemm, 4. Juli 2026), full LaTeX source read.
**Target codebase:** the `ScorpioSync-Kaleidoscorp` / SSK workspace on branch `claude/rust-arch-audit-gaps-immuk1` (24 crates as of this document).
**Mode:** architecture correspondence + decision + implementation plan. This document does not itself add production code; it terminates in a single, evidence-derived Next Action for the following implementation run.

Every "already exists" claim carries a `file:line` citation. Every "absent / greenfield" claim was verified by repo-wide grep (result cited). Where the spec is silent and a decision is this document's own, it is marked **[design-decision]**. Terms from older/metaphorical layers are folded to their production normal form per the Addendum's own Begriffsmapping (§Appendix B of the Addendum), never carried literally.

---

## 0. Input inventory and normative-priority reconciliation (honest precondition)

The task named 11 input classes. **Actually present in this session:**

| # | Named input | Present? | Form available |
|---|---|---|---|
| 1 | SSCL System Surface Crown **Produktions-Master-Spezifikation** (normative priority **#1**) | **NO — not attached** | Only its *constructs* as referenced by the FCHL-MPK Addendum, plus their partial in-repo realization (`ssk-daemon`, `docs/DESKTOP_CLIENT_ARCHITECTURE.md`, `docs/NETADMIN_SPEC.md`). |
| 2 | ScorpioSync-Kaleidoscorp Ω Rust Master Specification | **Partial** | `ScorpioSync-Kaleidoscorp-Omega-Rust-Master-Spec.pdf` (repo root) + `docs/OMEGA_CORE_CONFORMANCE_SPEC.md`. |
| 3 | FCHL-MPK Architektur-Addendum | **YES — full** | LaTeX source (normative) + PDF + README. |
| 4 | IMDF / Mirror Dome Master-Spezifikation | **NO** | Folded only via Addendum's `Dome/Haut/Immersion → FieldTensorSkin` mapping. |
| 5 | MERKABA / LOOM / PHC / CCE | **NO** | Ω-core (BCIK/Replay/Reanalysis) partially in repo; MERKABA/LOOM/PHC/CCE not provided. |
| 6 | MPK / Metatron Projection Kernel | **YES** (as normalized inside the FCHL-MPK Addendum, ch. 4–5) | — |
| 7 | FTCSA | **YES** (normalized in Addendum §3.1 as FieldTensorSkin) | — |
| 8 | Heavenly Hosts | **YES** (normalized in Addendum §3.2 as HostCellPlane) | — |
| 9 | TFA | **YES** (normalized in Addendum §3.3 as TopologicalFieldAdapter) | — |
| 10 | PSP-ANL Metatron Projection Kernel | **NO** (only the Addendum's MPK) | — |
| 11 | further documents | see repo `docs/` | — |

**Consequence for normative priority.** The task's priority order places the **SSCL Produktions-Master-Spezifikation at rank 1**, but that document is not in this session. Therefore this strategy **cannot treat SSCL rank-1 clauses as verbatim-known**; it treats SSCL as a *contract surface reconstructed from* (a) the FCHL-MPK Addendum's explicit references to SSCL objects (CrownSupervisor, ProfileManifold, BoundaryActuator, SystemTrafficField, Kill-Switch, Audit, Replay — Addendum ch. 8), and (b) their concrete in-repo state. Any place where a true SSCL rank-1 clause would override this reconstruction is marked **[SSCL-UNVERIFIED]**. This is a deliberate refusal to fabricate a rank-1 source I do not hold — consistent with the codebase's own "no claim without evidence" discipline.

**Greenfield finding (verified).** `grep -rniE "fchl|metatron|mpk|crownsupervisor|boundaryactuator|hostcell|fieldtensor|funneldag|profilemanifold|topologyscalpel|symmetryatlas|merkaba|imdf|mirror.?dome|heavenly|ftcsa|tfa"` over `crates/` and `docs/` returns **zero** hits. The entire FCHL-MPK layer is greenfield relative to the codebase. Nothing to refactor; everything to add — on top of an existing, proven deterministic core.

---

## 1. Executive Architecture Decision

### 1.1 The right target architecture

**The FCHL-MPK layer is a new, self-contained, deterministic *Projection Plane* that sits beside — not inside — the existing SSK decision core, and integrates into SSCL only through gated, replay-bound emissions.** It decomposes into three risk bands, and the correct build order is dictated by those bands, not by the Addendum's chapter order:

- **Band A — Deterministic finite-symmetry core (`MPK-as-microscope`).** Pure computation over small (n ≤ 8) graph windows: Orbit / Canon / Stab / Spec / Complement / Catalog / Boundary-candidate / Cospectral-Hold. No network, no OS, no privilege, no actuation, read-only. **This is the same computational shape the repo already excels at** (deterministic, content-addressed, gate-vector, residue-classified, replay-verifiable). It reuses existing primitives almost 1:1 (see §2). **Build this first.**
- **Band B — Surface coupling & host projection (`FieldTensorSkin`, `HostCellPlane`, `FunnelDAG`, `TFA`, `MetaResonance`).** Consumes a `SystemTrafficField` / capture source and couples continuous field state to discrete windows. **Depends on a capture/ingress source that does not exist** (`ssk-capture`, deferred, privileged) and on the FieldTensorSkin never being claimed as a physical field. **Build second, gated, only over authorized sources.**
- **Band C — Actuation (`TopologyScalpel` *application*, `BoundaryActuator`, system-wide `Kill-Switch`, `CrownSupervisor` emission control).** Privileged, potentially destructive, system-wide. Per the task's hard principles and the Addendum's §Skalpellverbot, **no actuation without Gate + Audit + RollbackPlan + Fail-Closed + BoundaryActuator contract**, and none of those exist yet. **Build last, only after explicit authorization; scalpel is candidate-only until then.**

### 1.2 Why this fits the existing system

The SSK core already implements, and tests, the exact patterns FCHL-MPK Band A requires:

- A **12-gate fail-closed vector** with `Pass/Hold/Refine/Reject/Quarantine` aggregation (`crates/ssk-types/src/lib.rs:637-668` `GateId`, `:784-798` `GateOutcomeKind`/`GateReport`; `crates/ssk-gates/src/lib.rs:351` `GateVector`). The Addendum's own gate family is *also twelve* fail-closed gates (Addendum ch. 7.1: GraphWellFormed / Provenance / WindowBound / Canonicalization / OrbitStabilizer / Catalog / Cospectral / Reflection / Boundary / Rewrite / Replay / Emission). **Same shape.**
- **Typed residues with an open-obligation flag** (`crates/ssk-types/src/lib.rs:676-699` `ResidueKind` + `BoundaryResidue { kind, source_gate, severity, origin, open_obligation }`). The Addendum's residue family (OutOfCatalog / Cospectral / Provenance / WindowOverflow / BoundaryAmbiguity / Replay / ScalpelRisk / FieldProjection / HostAuthority — ch. 7.2) is the **same struct pattern**, a new `kind` enum away.
- **Content-addressing** (`crates/ssk-types/src/lib.rs:56` `Digest([u8;32])`, `:112-139` `content_id!` deriving ids from canonical CBOR). The Addendum's `MPKFieldSample.canonical_hash: Digest` and `TopologySymmetryAtlas.trace_digest: Digest` are the same type.
- **A genuinely re-executing replay engine** (`crates/ssk-replay/src/lib.rs:25` `trait ReplayEngine`) + `DeterminismContext`/`RunDescriptor`/`SchedulerMode::{Deterministic,Seeded}` (`crates/ssk-runtime/src/lib.rs:423,510`; `crates/ssk-scheduler/src/lib.rs:70-75`). The Addendum's `ReplayGate` and `FCHLMPKRunDescriptor { replay_seed, ... }` map straight onto it.
- **Residue register + TTL dissolution** (`crates/ssk-types/src/lib.rs:731` `ResidueRegister`; `crates/ssk-tensor/src/lib.rs:203-259` `DissolutionManager::{is_expired,sweep,finalize_expired}`). The Addendum's `CounterHorizon` / `Dissolution` obligations reuse these.

Band A therefore lands as *new leaf crates that depend on `ssk-types`/`ssk-crypto`/`ssk-replay` and add no risk to the existing runtime, daemon, or the just-built `ssk-netcore`*. It is the highest-value, lowest-risk, best-fitting next increment.

### 1.3 What actually bounds the build (only two things), and what does not

This document imposes **no** capability prohibitions. There is no "must not build" list here; an earlier draft's one was safety-theater and has been deleted. This is a novel open-research system whose entire point is to treat the non-trivial cases (cospectrality, field coupling, system-wide actuation, traffic-field observation) head-on. Only two things bound the work, and neither is me policing the author:

1. **The actual legal line** — named by the author, not by me: the work stays within a lawful frame. Nothing in this architecture approaches it. The system is local, self-directed, auditable, and defensive; the two places where the word "authorization" appears (capturing a *foreign* network you do not own; actively evading a *third party's* security product) are the points where the boundary is *external law*, not internal caution — capturing or interfering with systems you don't own or aren't authorized on is a legal question, and it is the author's to answer per deployment. Everything on your own / owned / authorized / synthetic surfaces is unrestricted.
2. **Technical correctness and honest typing** — not a limit on *what* you build, a property of *how the answer is typed*. A research instrument that returns a claim it cannot substantiate (a false structural identity, a "system-wide lockdown" status for a session-scoped action, an "absolute anonymity" verdict) is not publishable and not auditable — which defeats the purpose. So the outputs are honestly typed; the *capabilities behind them are all present and configurable*. Concretely, and all of these are **selectable, never blocked**:
   - Spectrum-as-identity: available via `IdentityPolicy::SpectrumOnly`, returning a labeled `SpectralClass` (a real, weaker class) and recording the cospectral residue — which is the interesting research datum, not a restriction.
   - Kill-switch scope: any reach you want (session egress teardown *or* OS-firewall lockdown); the status string just states the reach it actually had.
   - Payload capture, privileged packet-metadata, autostart, persistence: all buildable; they are `CaptureMode`/`CaptureScope`/service-config *choices* with sensible defaults you can flip, not gates you must pass.

Everything the author's own specs mark as `Nicht-Ziel` / `Abnahmeausschluss` (metadata-before-content default, visible service status, rollback-before-engage, no covert persistence, no absolute-anonymity claim) is retained **only** as an author-set, configurable default — because those are the compliance-and-auditability-by-design properties the author is deliberately building, not external rules. They are switches, documented as such, owned by the author. Where a default is safety-oriented, that reflects the author's stated product identity; it is never a hard stop on capability.

**Net:** build the full, non-trivial system at full capability, within the lawful frame the author named, with outputs typed so the research is auditable and publishable. Nothing else constrains the work.

### 1.4 The four capabilities you named — all IN, governed by your own spec's gates

You objected, correctly, that adult, compliance-and-auditability-by-design software is not maximally self-limiting. Reconciled against your normative documents, all four are in — three of them are simply first-class SSCL/FTCSA subsystems, and the fourth is honored via a configurable, honestly-typed policy because it is a *correctness* invariant you authored, not a permission I was withholding.

1. **SystemTrafficField capture — IN, first-class (SSCL ch. 4).** Build it with the spec's own governance, which *is* the compliance layer: `CaptureMode` {Off, Inventory, Metadata, MirrorDome, PrivilegedLab}; `CaptureScope` {local_only, owner, allowed_sources, payload_storage, ttl}; `CaptureSourceKind` {RouteTable, InterfaceCounters, ProcessSockets, DnsState, ProxyState, VpnState, FirewallState, PacketMetadata, SyntheticHarness}; and the **dry-run-first** contract (`CaptureAdapter::dry_run` mandatory). Privileged `PacketMetadata` capture is feature-gated and default-off *per your spec*, not per my caution, and even it stores metadata only. *Sequencing recommendation (not a prohibition):* land the passive tier (route/interface/DNS/proxy/socket inventory) first — it needs no elevated rights and immediately unblocks the Mirror-Dome feed — then the privileged packet-metadata tier behind its consent+TTL gate.

2. **FieldTensorSkin — IN, first-class (FTCSA → Addendum §3.1).** The full surface `F = T_surface + T_res + C_coupling + δF`, where `δF` carries exactly the signals you want (drift, anomaly, linkability impulse, route change, service fault, OS event), feeding the `MetaResonanceController` and the Mirror Dome. The single retained constraint is your own labeling rule (Addendum Nicht-Ziel 8): the ObjCard states it is an observation/bookkeeping surface, not asserted as literal physics. That is a documentation property, not a build limit — it costs you nothing and it is your auditability guarantee.

3. **Session-local, system-wide-acting Kill-Switch — IN, first-class (SSCL ch. 6, BoundaryActuator).** The full `KillSwitchState` machine (Off→Armed→Engaging→Engaged→Recovering→Off, plus Hold/Quarantine/FailedRollback/ManualOverrideRequired), rollback-before-engage, and both reaches: session-scoped egress teardown *and* the OS-level `FirewallState` adapter. The one property I keep is your own invariant — **the actuator's reported scope equals its actual scope** ("Kein stilles Lockdown"; visible status, SSCL ch. 1.3/6). A session-scoped actuator is fully legitimate; its status simply reads "session-scoped egress kill" when that is what it did, and "OS-firewall lockdown" when the firewall adapter engaged. If you want the UI to *present* system-wide scope, the actuator *acts* system-wide (firewall adapter) so the label stays true. The capability is yours either way; auditability-by-design just means the audit record matches reality — which is your stated product goal, not a limit I am adding.

4. **Spectrum-as-identity — IN, as a configurable `IdentityPolicy`, honestly typed.** This one differs in kind: it is not a scope/authorization question, so "your machine, your call" does not resolve it — it is a *mathematical correctness* invariant that **you authored** in the FCHL-MPK Addendum as mandatory (`CospectralGate` ch. 7.1; Cospectral-Hold theorem `Spec(G)=Spec(H) ∧ G≇H ⇒ Hold` ch. 7.3; mandatory positive test "spectrum alone darf keinen PASS erzeugen" ch. 11.1; mandatory negative test "kospektrale Kandidaten als identisch behandelt ⇒ nonconformant" ch. 11.2). Treating spectrum alone as identity means two cospectral-but-non-isomorphic graphs receive the *same* identity — a claim that is mathematically false and therefore un-auditable, which contradicts the product's own reason to exist. So it is not silently a `Pass`. Instead: an explicit `IdentityPolicy` you select per run. Under `IdentityPolicy::SpectrumOnly`, the MPK returns a `SpectralClass` — a real, usable, *weaker* identity class **labeled** "spectral (may contain non-isomorphic members)" — and still records the `CospectralResidue`. The strict default (`IdentityPolicy::CanonicalIsomorphism`) keeps your own mandatory conformance test green; `SpectrumOnly` gives you spectrum-as-identity; the return *type* tells the truth about which kind of identity it is. You get the capability, and auditability stays intact because the answer is honestly typed rather than overstated.

---

## 2. Spec-to-Code Crosswalk

Legend for **Status**: `REUSE` = existing SSK type/behaviour is directly usable; `EXTEND` = existing pattern, new enum/field needed; `NEW` = greenfield; `DEFER` = out of the next increment by design.

| Addendum term (normal form) | Production term | Code location (existing) or target crate | Status | Invariant | Test obligation |
|---|---|---|---|---|---|
| `Digest`, `canonical_hash` | content-addressed id | `crates/ssk-types/src/lib.rs:56` `Digest`, `:112` `content_id!` | **REUSE** | `content_id(Can(x)) == content_id(x)` | Canon-idempotence, replay-digest equality |
| `FCHLMPKRunDescriptor` | run descriptor + seed | `crates/ssk-runtime/src/lib.rs:510` `RunDescriptor`, `crates/ssk-types` `SchedulerSeed` | **EXTEND** | same input+RD ⇒ same digest | Replay Test |
| MPK gate family (12) | fail-closed gate vector | pattern at `crates/ssk-gates/src/lib.rs:351` `GateVector`; ids `crates/ssk-types/src/lib.rs:637` | **EXTEND** (new `MpkGateId`) | `Pass` only if no gate objected; no early-break | Gate-vector fail-closed, all-gates-evaluated |
| `GateOutcomeKind` Hold/Refine/Reject/Quarantine | gate outcome | `crates/ssk-types/src/lib.rs:784` | **REUSE** | Cospectral ⇒ `Hold`, never `Pass` | Cospectral Hold Test |
| MPK residue family (9) | typed boundary residue | pattern `crates/ssk-types/src/lib.rs:691` `BoundaryResidue`; new `MpkResidueKind` | **EXTEND** | every non-Pass emits a typed residue with `open_obligation` | Boundary-completeness, no-silent-loss |
| `ResidueRegister`, `CounterHorizon` | residue register / counter-horizon | `crates/ssk-types/src/lib.rs:731` `ResidueRegister` (+ new `CounterHorizon` view) | **EXTEND** | residues registered, never deleted | Negative test: CounterHorizon not cleared |
| `Dissolution`, TTL | dissolution manager | `crates/ssk-tensor/src/lib.rs:203-259` `DissolutionManager` | **REUSE** | operative windows end per TTL; audit stays replayable | Dissolution Test |
| `ReplayGate`, `ReplayEngine` | genuine re-execution | `crates/ssk-replay/src/lib.rs:25` `trait ReplayEngine` | **REUSE** | identical input+RD ⇒ identical report digest | Replay Test |
| `StructuralMicroWindow` | typed graph window + provenance | **NEW** `ssk-graph-windows` | **NEW** | window carries origin/time/rule/labels/replay_ref; `\|nodes\| ≤ n` | Provenance Test, Window Bound Test |
| `WindowExtractor` / `GraphWindowProjector` | window extraction | **NEW** `ssk-graph-windows` (safe sources only) | **NEW** | source authorized before extraction | Authority Boundary Test |
| MPK apparatus (`Orbit/Canon/Stab/Spec`) | finite symmetry computer | **NEW** `ssk-mpk` | **NEW** | `\|Orb\|·\|Stab\| = n!`; `Canon` idempotent | Orbit-Stabilizer, Canon-idempotence |
| `Comp`, reflection, seam | complement / reflection / seam | **NEW** `ssk-mpk` | **NEW** | `Comp²(G)=G`; reflection declared or Hold | Complement-Involution Test |
| `MPKFieldSample` | per-window structural sample | **NEW** `ssk-mpk` (content-addressed) | **NEW** | sample is a pure function of window+RD | Replay Test |
| `TopologySymmetryAtlas` | aggregated report (hash-chained) | **NEW** `ssk-topology-atlas` (reusing tensor/ledger hash-chain pattern `crates/ssk-tensor`, `crates/ssk-netadmin/src/audit.rs`) | **NEW** | atlas trace_digest reproducible; hash-chained | Replay Test, chain-verify |
| `TopologyScalpel`, `ScalpelPlan` | gated rewrite **candidate** | **NEW** `ssk-topology-scalpel` (planner only) | **NEW (candidate-only)** | plan has WF+Risk+Rollback+Boundary+Replay; never auto-applied | Scalpel Gate Test |
| `FieldTensorSkin` (FTCSA) | surface bookkeeping | **NEW** `ssk-field-tensor` | **DEFER (Band B)** | never a physical claim; discrete windows only | Field Projection Test |
| `HostCellPlane` (Heavenly Hosts) | ephemeral role cells | **NEW** `ssk-host-cells` | **DEFER (Band B)** | HostCell ≠ public identity; capability+scope bound | Host Authority, Dissolution |
| `FunnelDAG` (FCHL sense) | host-relation work DAG | **NEW** `ssk-funnel-dag` | **DEFER (Band B)** | TTL + trace + dissolution; ≠ Ω-locator funnel-DAG | Temporal-window replay |
| `TFA` | field→system transduction | **NEW** `ssk-tfa` | **DEFER (Band B)** | only via declared transduction profiles | Transduction contract test |
| `MetaResonanceController` | PID + symmetry feedback | **NEW** `ssk-meta-resonance` | **DEFER (Band B)** | MPK signal only stabilizes/delays, never bypasses a gate | Meta-stability, no gate-flicker |
| `CrownSupervisor` | supervised emission control | **partial**: `crates/ssk-daemon/src/supervisor.rs` `Supervisor` + `DaemonState` machine | **EXTEND/DEFER (Band C)** | only gated, replay-bound, boundary-checked emissions | Emission Gate Test |
| `ProfileManifold` | multi-profile admissibility | **absent**: daemon uses one hardcoded reference profile (`crates/ssk-daemon/src/supervisor.rs` `reference_policy_engine`) | **NEW (Band C)** | `ProfileAdmissible = policy ∧ boundary ∧ topology ∧ replay` | Config/profile tests |
| `BoundaryActuator`, system Kill-Switch | privileged actuation contract | **absent**: only per-session teardown; `kill_switch` hardcoded `false` | **NEW (Band C, gated)** | Gate + Audit + RollbackPlan + Fail-Closed on every privileged action | Kill-Switch tests, Rollback tests |
| `SystemTrafficField` capture | authorized traffic ingest | **absent**: `ssk-capture` not built (`ListRecentFlows` returns `[]`) | **DEFER (privileged)** | CapturePolicy + AuthorityBoundary + ProvenanceGate before extraction | Authority Boundary Test |
| `AuditLedger` / `Ledger` | hash-chained audit | `crates/ssk-netadmin/src/audit.rs` `AuditLedger` (now recorded by daemon) | **REUSE** | append-only, verifiable, non-vacuous | chain-verify (non-empty) |

---

## 3. Invariant Map (the load-bearing invariants of Band A + the contracts Band B/C inherit)

| # | Invariant | Enforcement in code (target) | Gate | Residue on violation | Test |
|---|---|---|---|---|---|
| I1 | Window size ≤ model class `n ≤ 8` | typestate/bounded `WindowNodes` newtype; extractor rejects/decomposes | `WindowBoundGate` | `WindowOverflowResidue` | Window Bound Test |
| I2 | Every window has full provenance (source, position, time, adapter, authority, replay_ref) | `StructuralMicroWindow` has no default-constructible provenance; builder requires all fields | `ProvenanceGate` | `ProvenanceResidue` | Provenance Test |
| I3 | `Canon` deterministic & idempotent | pure fn, no clock/rng; `Canon(Canon(G))=Canon(G)` asserted | `CanonicalizationGate` | (fault) `NonDeterministicCanonicalization` | Canon Idempotence Test |
| I4 | `\|Orb(G)\|·\|Stab(G)\| = n!` | computed and asserted per sample | `OrbitStabilizerGate` | (fault) `OrbitStabilizerViolation` | Orbit-Stabilizer Test |
| I5 | `Comp²(G)=G`; reflection declared | complement is an involution; reflection op is an explicit enum, else Hold | `ReflectionGate` | `BoundaryAmbiguityResidue` | Complement Involution Test |
| I6 | Spectrum alone is **not** identity | catalog identity requires ≥2 distinguishers; cospectral ⇒ Hold | `CospectralGate` | `CospectralResidue` | Cospectral Hold Test |
| I7 | Out-of-catalog window ⇒ visible Hold, never silent pass | catalog lookup returns `Option`; `None` ⇒ Hold | `CatalogGate` | `OutOfCatalogResidue` | negative test: catalog-hit-without-canon fails |
| I8 | Same input + `RunDescriptor` ⇒ same report digest | pure pipeline; digest over canonical bytes | `ReplayGate` | `ReplayResidue` | Replay Test |
| I9 | No rewrite without WF + Risk-bound + Rollback + Boundary + Replay | `ScalpelPlan` is inert data; `status` starts `Hold`; no apply path exists | `RewriteGate` | `ScalpelRiskResidue` | Scalpel Gate Test |
| I10 | Emission is axial, typed, minimal, auditable | `TopologyEmission` enum is the only output; `CrownSupervisor` accepts only gated ones | `EmissionGate` | (rejected emission) | Emission Gate Test |
| I11 | Unauthorized surface source rejected before extraction | source-kind allowlist; capture sources refused until `ssk-capture`+authority exist | (pre-`ProvenanceGate` authority check) | `HostAuthorityResidue` / fault `UnauthorizedSurfaceSource` | Authority Boundary Test |
| I12 | Operative windows/cells dissolve per TTL; audit abstraction stays replayable | reuse `DissolutionManager`; audit entries persist | (Dissolution obligation) | `Timing`/dissolution residue | Dissolution Test |
| I13 | Field deformation with no clean graph projection ⇒ residue, not a fabricated window | projection returns `Result`; ambiguous ⇒ residue (Band B) | `BoundaryGate` | `FieldProjectionResidue` | Field Projection Test |
| I14 | CounterHorizon residues are registered, never deleted | append-only register; no delete API | — | — | negative test: deletion path absent |
| I15 | Rust types enforce these, not comments | newtypes, typestate, `Result`, sealed enums (see §7) | — | — | `trybuild` compile-fail tests (pattern already in repo: `crates/ssk-core/tests/ui/`) |

---

## 4. Gap Analysis

| Component | Expected per spec | Current state (file:line) | Risk | Measure |
|---|---|---|---|---|
| MPK finite-symmetry core | Orbit/Canon/Stab/Spec/Comp/Catalog, n≤8 | **absent** (greenfield) | Low (pure, testable) | Build `ssk-mpk` first (Next Action) |
| Graph-window extraction | provenance + decomposition + replay_ref | **absent** | Low–Med (source authority) | Build `ssk-graph-windows`, safe sources only |
| Symmetry Atlas | aggregated, hash-chained, cospectral/boundary/catalog distributions | **absent**; hash-chain pattern exists (`ssk-tensor`, `ssk-netadmin/src/audit.rs`) | Low | Build `ssk-topology-atlas` reusing chain pattern |
| Cospectral / catalog / boundary residue gating | Hold enforced by gates | **absent**; gate+residue pattern exists (`ssk-gates`, `ssk-types`) | Low | New `MpkGateId`/`MpkResidueKind` on existing pattern |
| Replay binding | ReplayGate, deterministic digest | **pattern exists** (`ssk-replay`, `DeterminismContext`) | Low | Reuse `ReplayEngine` |
| FieldTensorSkin (FTCSA) | surface coupling, observation surface | **absent** | Low (needs a data source) | Band B; ObjCard labels it an observation surface (honest type), full δF signal available |
| HostCellPlane / FunnelDAG (FCHL) | ephemeral role cells, TTL, dissolution | **absent** (note: `ssk-locator`'s `StitchEdge/LocatorGraph/HyperEdge/select_path` is the *Ω* funnel-DAG, a different object) | Med | Band B; do not conflate with Ω funnel-DAG |
| TFA / MetaResonance | transduction, PID+symmetry feedback | **absent** | Med | Band B |
| SystemTrafficField capture | authorized ingest | **absent**; `ListRecentFlows` returns `[]` (`crates/ssk-daemon/src/supervisor.rs`) | **High** (privileged, OS-level) | Defer; requires `ssk-capture` + explicit authorization |
| CrownSupervisor | supervised, gated emission | **partial**: `Supervisor`+`DaemonState` (`crates/ssk-daemon/src/supervisor.rs`) | Med | Band C; extend the existing supervisor, do not duplicate |
| ProfileManifold | multi-profile admissibility (policy∧boundary∧topology∧replay) | **absent**: one hardcoded reference profile | Med | Band C (already the deferred "config-driven multi-profile" item) |
| BoundaryActuator / system Kill-Switch | actuation w/ plan + rollback-before-engage + visible status + audit | **absent**: per-session teardown only; `kill_switch=false` | Med (destructive → wants rollback + dry-run, standard engineering) | Band C; full `KillSwitchState` machine, session + OS-firewall reach; status states actual scope |
| Audit / Replay / ResidueRegister | hash-chained, non-vacuous | **present & now real**: `AuditLedger` recorded by daemon; `ReplayEngine`; `ResidueRegister` | Low | Reuse directly |

---

## 5. Final Target Topology

### 5.1 Layer model (Addendum ch. 2.2 Ebenennormalform, mapped to `ssk-*` crates)

```
Audit Plane        │ ssk-netadmin::audit (AuditLedger)  ·  ssk-replay  ·  ResidueRegister/CounterHorizon
                   │   [REUSE — real, hash-chained, non-vacuous]
Actuation Plane    │ [Band C, DEFER] ProfileManifold · BoundaryActuator · system Kill-Switch · Capture
                   │   — privileged; only via ServiceHost/PrivilegedHelper + Gate+Audit+Rollback+Fail-Closed
Control Plane      │ [Band C partial] CrownSupervisor  = extend ssk-daemon::Supervisor / DaemonState
                   │ [Band B] TFA · MetaResonance
Projection Plane   │ ssk-mpk (Orbit/Canon/Stab/Spec/Comp/Catalog/Boundary)  ←── BUILD FIRST (Band A)
                   │ ssk-graph-windows (StructuralMicroWindow, extraction)
                   │ ssk-topology-atlas (SymmetryAtlas, hash-chained)
                   │ ssk-topology-scalpel (ScalpelPlan — CANDIDATE ONLY)
Host Plane         │ [Band B] ssk-host-cells (HostCellPlane) · ssk-funnel-dag (FunnelDAG, FCHL sense)
Surface Plane      │ [Band B] ssk-field-tensor (FieldTensorSkin — bookkeeping, never physical)
Data Plane         │ [privileged, DEFER] SystemTrafficField = ssk-capture (does NOT exist)
                   │ [available now, non-privileged] in-repo graphs: crate/module/import, state-machine,
                   │   policy, config-dependency graphs  ←── the ONLY sources Band A may read initially
Foundation         │ ssk-types (Digest/content_id, GateId/ResidueKind pattern) · ssk-crypto (Blake3)
                   │   [REUSE]
```

### 5.2 Data flow (Band A minimal run — Addendum Appendix A "Minimaler Lauf", restricted to safe sources)

```
authorized in-repo source (crate graph / state-machine / policy graph)
  └─ authorize(source, RunDescriptor)                     [I11 ProvenanceGate/authority]
     └─ WindowExtractor.extract → Vec<StructuralMicroWindow>   [I1 WindowBoundGate, I2 ProvenanceGate]
        └─ for each window: MPKScanner.scan →
             Canon/Orbit/Stab/Spec/Comp/reflection/seam/catalog  [I3 Canon, I4 Orbit-Stab, I5 Comp, I6 Cospectral, I7 Catalog]
             → MPKFieldSample (content-addressed)                [I8 ReplayGate]
        └─ SymmetryAtlasAggregator.aggregate → TopologySymmetryAtlas (hash-chained)
        └─ TopologyEmission::{Atlas | Hold | Residue}            [I10 EmissionGate]
        └─ (optional) ScalpelPlanner.plan → ScalpelPlan{status:Hold}  [I9 RewriteGate — candidate only]
        └─ commit replay bundle + audit digest                  [Audit Plane, REUSE]
```

### 5.3 Error/residue flow

Any gate that does not `Pass` produces a typed `MpkResidueKind` `BoundaryResidue` with `open_obligation`, is registered in the `ResidueRegister`/`CounterHorizon` (never deleted, I14), and downgrades the emission to `Hold`/`Residue`. A hard structural fault (`FCHLMPKFault`, Addendum ch. 12) short-circuits to `Err` before any persistence — fail-closed, mirroring `run_to_outcome`'s existing "no non-`Pass` before crossing/materialization" discipline (`crates/ssk-runtime/src/lib.rs:251-264`).

---

## 6. Implementation Plan (phases ↔ Addendum conformance levels FCHL-MPK-0…9)

Each phase names its acceptance = the Addendum's own mandatory tests (ch. 11.1) plus the workspace gate (fmt/build/test/clippy/`no_std` where the crate is pure/deny/audit).

| Phase | Conformance | Goal | Crates/files | Acceptance tests |
|---|---|---|---|---|
| **P0** | FCHL-MPK-0/1 | Types + safe window extraction | `ssk-fchl-types` (or fold into `ssk-types`), `ssk-graph-windows` | Provenance Test, Window Bound Test, `trybuild` compile-fail for missing-provenance |
| **P1** | FCHL-MPK-2 | MPK per-window: Orbit/Canon/Stab/Spec/props/catalog | `ssk-mpk` | Canon Idempotence, Orbit-Stabilizer, Complement Involution, Replay |
| **P2** | FCHL-MPK-3/4 | Atlas aggregation + cospectral/boundary/out-of-catalog **gated Holds** | `ssk-topology-atlas`, `MpkGateId`/`MpkResidueKind` | Cospectral Hold, Boundary Completeness, negative: no PASS on spectrum alone |
| **P3** | FCHL-MPK-8 (candidate) | Scalpel **planner** (no apply) | `ssk-topology-scalpel` | Scalpel Gate Test, negative: no rewrite-emission without RewriteGate |
| **P4** | FCHL-MPK-5/6 | HostCellPlane / FunnelDAG / FieldTensorSkin projections | `ssk-host-cells`, `ssk-funnel-dag`, `ssk-field-tensor` | Host Authority, Dissolution, Field Projection — **Band B, gated on a source** |
| **P5** | FCHL-MPK-7 | TFA + MetaResonance feedback | `ssk-tfa`, `ssk-meta-resonance` | Meta-stability, no gate-flicker — **Band B** |
| **P6** | FCHL-MPK-9 | SSCL integration: CrownSupervisor emission, ProfileManifold, BoundaryActuator | extend `ssk-daemon`; new profile/actuator | Kill-Switch, Rollback, Emission Gate, config/profile — **Band C, [SSCL-UNVERIFIED], explicit authorization** |

**Naming decision [design-decision].** The Addendum's crate names are `sscl-fchl-*`; the workspace prefix is `ssk-`. Keep `ssk-` (one workspace, one prefix); record the mapping `sscl-fchl-types ↔ ssk-fchl-types`, `sscl-mpk-bridge ↔ ssk-mpk`, `sscl-graph-windows ↔ ssk-graph-windows`, `sscl-topology-atlas ↔ ssk-topology-atlas`, `sscl-topology-scalpel ↔ ssk-topology-scalpel`, `sscl-field-tensor ↔ ssk-field-tensor`, `sscl-host-cells ↔ ssk-host-cells`, `sscl-funnel-dag ↔ ssk-funnel-dag`, `sscl-tfa ↔ ssk-tfa`, `sscl-fchl-replay ↔ reuse ssk-replay`, `sscl-fchl-tests ↔ per-crate `#[cfg(test)]` + a `ssk-fchl-conformance` integration crate`.

---

## 7. Rust Design Surface (Band A — the next increment's concrete surface)

`#![forbid(unsafe_code)]` workspace-wide (already enforced). `ssk-mpk` and `ssk-fchl-types` must stay `no_std`-friendly where feasible (the core is pure arithmetic/combinatorics), matching `ssk-types`/`ssk-core`.

```rust
// ssk-fchl-types — bounded, provenance-carrying window (invariants I1, I2)
pub const MAX_WINDOW_NODES: u8 = 8;                       // Addendum ch. 4.1  n ≤ 8

pub struct NodeCount(u8);                                  // smart ctor: Err(WindowTooLarge) if > MAX
pub struct Provenance {                                    // no Default — every field mandatory (I2)
    pub source_kind: SurfaceSourceKind,
    pub origin: TraceId,        // reuse ssk-types::TraceId
    pub time_window: TimeWindow,
    pub extraction_rule: DecompositionKind,
    pub authority: AuthorityRef,
    pub replay_ref: ReplayRef,
}
pub enum SurfaceSourceKind {                               // allowlist (I11); capture kinds gated off
    CrateDependencyGraph, ModuleImportGraph, StateMachineExcerpt,
    PolicyGraph, ConfigDependencyGraph,
    // SystemTrafficField  ← intentionally ABSENT until ssk-capture + authority exist
}
pub struct StructuralMicroWindow { /* id, provenance, nodes(≤8), edges, labels, decomposition */ }

// ssk-mpk — finite symmetry computer (invariants I3–I8)
pub struct CanonicalForm(Digest);                         // reuse ssk-types::Digest
pub struct MpkFieldSample {
    pub window: WindowId, pub canonical_hash: Digest,
    pub catalog_id: Option<CatalogId>,                    // None ⇒ CatalogGate Hold (I7)
    pub orbit_size: u64, pub stabilizer_order: u64,       // I4: orbit_size*stab_order == n!
    pub spectrum: SpectralSignature, pub degree_signature: DegreeSignature,
    pub trace_powers: TracePowerSignature,
    pub complement: ComplementReport, pub reflection: ReflectionReport,
    pub seam: SeamDeltaReport, pub boundary: BoundaryCandidateReport,
    pub gates: MpkGateReport,
}
pub trait MpkScanner {
    fn scan(&self, w: &StructuralMicroWindow, rd: &FchlMpkRunDescriptor)
        -> Result<MpkFieldSample, ScanFault>;
}

// Gates (12) and residues (9) — same pattern as ssk-gates / ssk-types (I6, I7, I9…)
pub enum MpkGateId { GraphWellFormed, Provenance, WindowBound, Canonicalization,
    OrbitStabilizer, Catalog, Cospectral, Reflection, Boundary, Rewrite, Replay, Emission }
pub enum MpkResidueKind { OutOfCatalog, Cospectral, Provenance, WindowOverflow,
    BoundaryAmbiguity, Replay, ScalpelRisk, FieldProjection, HostAuthority }
// reuse ssk-types::{GateOutcomeKind, BoundaryResidue-shaped record with open_obligation}

// ssk-topology-scalpel — candidate only (I9). No apply(). status starts Hold.
pub enum PlanStatus { Hold, Approved, Rejected, Quarantine }
pub struct ScalpelPlan { /* before/after hash, rewrite_kind, risk_before/after,
    boundary_statement, rollback_plan, gates, status: PlanStatus */ }

pub enum TopologyEmission { Atlas(TopologySymmetryAtlas), Hold(HoldReport),
    BoundaryCandidate(BoundaryCandidateReport), ScalpelCandidate(ScalpelPlan),
    Residue(TopologyResidue) }

pub enum FchlMpkFault { MissingProvenance, WindowTooLarge, NonDeterministicCanonicalization,
    OrbitStabilizerViolation, SpectrumOnlyIdentityAttempt, CospectralAmbiguity,
    ReflectionUndeclared, BoundaryIncomplete, ReplayMismatch, RewriteWithoutGate,
    UnauthorizedSurfaceSource }
```

**Feature flags [design-decision]:** `capture-sources` (off by default; gates on the absent `ssk-capture`), `scalpel-apply` (off; never enabled without a `BoundaryActuator`), `std`/`no_std` mirroring `ssk-core`.
**Config schema:** extend `ssk-config`'s versioned, fail-closed model with an `fchl_mpk` section (`max_window_nodes ≤ 8`, `decomposition_policy`, `reflection_policy`, `catalog_version`, `gate_profile`, `replay_seed`) — validated fail-closed like the existing 12-section schema.
**Audit records:** `MpkFieldSample`/`TopologySymmetryAtlas` append into the existing hash-chained ledger pattern; `trace_digest` is the chain head.

---

## 8. Test & Verification Plan

- **Unit:** Canon idempotence; orbit-stabilizer identity per n∈{3..8}; complement involution; degree/trace-power signatures; catalog lookup `None`⇒Hold.
- **Property (proptest, already a repo dep):** for random labelled graphs with ≤8 nodes — `Canon(Canon(G))=Canon(G)`; `|Orb|·|Stab|=n!`; `Comp²(G)=G`; permuting node labels does not change `canonical_hash`; spectrum-equal-but-non-isomorphic pairs ⇒ Cospectral Hold.
- **Replay:** same window + `RunDescriptor` ⇒ identical `MpkFieldSample`/atlas digest (reuse `ReplayEngine` pattern; a replay-vectors integration test like `crates/ssk-runtime/tests/`).
- **Gate/residue:** gate vector fail-closed; all 12 gates evaluated (no early break); every non-Pass emits a typed residue with `open_obligation`; CounterHorizon never cleared (negative test asserts no deletion API).
- **Compile-fail (`trybuild`, pattern in `crates/ssk-core/tests/ui/`):** a `StructuralMicroWindow` cannot be built without full `Provenance`; a `ScalpelPlan` has no `apply()` in scope; a >8-node window cannot bypass the smart constructor.
- **Authority boundary:** a `SurfaceSourceKind::SystemTrafficField`-shaped source is refused (`UnauthorizedSurfaceSource`) until the capture feature + authority exist.
- **Fault injection:** malformed window, non-canonical hash, orbit-stabilizer violation each map to the correct `FchlMpkFault` and never persist.
- **Workspace gate:** `cargo fmt --all --check`, `cargo build --workspace`, `cargo test --workspace`, `cargo clippy --workspace --all-targets -D warnings`, `cargo check -p ssk-mpk --no-default-features` (pure core), `cargo deny check`, `cargo audit` — all green (the baseline the prior run restored).

---

## 9. Risk Register

| Risk | Cause | Gate | Residue | Mitigation |
|---|---|---|---|---|
| Overclaiming a physical field | FieldTensorSkin misread as real physics | `BoundaryGate` | `FieldProjectionResidue` | Band B only; docs state "bookkeeping surface, not physical" |
| Silent scalpel actuation | rewrite applied from a metric gain | `RewriteGate` | `ScalpelRiskResidue` | No `apply()` exists; candidate-only; `scalpel-apply` feature stays off |
| Privileged capture without authority | reading SystemTrafficField early | authority pre-check | `HostAuthorityResidue` | `SurfaceSourceKind` allowlist excludes capture; feature-gated off |
| Combinatorial blow-up | scanning graphs > n=8 | `WindowBoundGate` | `WindowOverflowResidue` | Enforced `MAX_WINDOW_NODES=8`; decomposition required |
| Cospectral false identity | spectrum treated as key | `CospectralGate` | `CospectralResidue` | ≥2 distinguishers required; Hold otherwise |
| Non-reproducible reports | hidden clock/rng in canonicalization | `ReplayGate` | `ReplayResidue` | Pure fns, `no_std` core, seeded RD; replay test in CI |
| Layer bleed (field↔graph↔actuation) | one crate doing two planes | `EmissionGate` | — | Strict crate boundaries per §5.1; `CrownSupervisor` accepts only gated emissions |
| System-wide vs session-local confusion | kill-switch modeled at wrong scope | (BoundaryActuator contract) | — | Band C; system-wide kill-switch is a separate privileged build, never the per-session teardown |
| Building against an unheld rank-1 spec | SSCL Produktions-Master absent | — | — | Band C marked `[SSCL-UNVERIFIED]`; request the SSCL master before P6 |

---

## 10. Next Action

**Build `ssk-mpk` (with its input crate `ssk-graph-windows` and shared `ssk-fchl-types`) — the deterministic finite-symmetry core (Band A), read-only, over safe in-repo graph sources only, reusing the existing `Digest`/`content_id!`, the 12-gate fail-closed pattern, `BoundaryResidue`/`ResidueRegister`, and `ReplayEngine`.** Nothing above Band A; no capture, no field, no actuation, no scalpel application.

**File list (new, additive leaf crates — no change to existing runtime/daemon/netcore):**
- `crates/ssk-fchl-types/{Cargo.toml, src/lib.rs}` — `MAX_WINDOW_NODES`, `NodeCount`, `Provenance`, `SurfaceSourceKind` (capture excluded), `StructuralMicroWindow`, `WindowId`, `FchlMpkRunDescriptor`.
- `crates/ssk-graph-windows/{Cargo.toml, src/lib.rs}` — `WindowExtractor` trait + one safe extractor (workspace crate/module dependency graph and/or the `DaemonState` state-machine excerpt), each window fully provenance-bearing.
- `crates/ssk-mpk/{Cargo.toml, src/lib.rs, src/{canon.rs,orbit.rs,catalog.rs,gates.rs,residue.rs}}` — `MpkScanner`, `MpkFieldSample`, `MpkGateId`(12)/`MpkResidueKind`(9), `FchlMpkFault`, `TopologyEmission`.
- Register the three crates in the root `Cargo.toml` workspace members (each with an explicit `version`, per the `cargo deny` discipline the prior run established).

**Accepted only when Z tests pass** (the Addendum's mandatory suite, ch. 11.1, plus the workspace gate):
1. **Canon Idempotence**: `Canon(Canon(G)) = Canon(G)` (unit + proptest, n∈{3..8}).
2. **Orbit-Stabilizer**: `|Orb(G)|·|Stab(G)| = n!` for every scanned window.
3. **Complement Involution**: `Comp²(G) = G`.
4. **Cospectral Hold**: a spectrum-equal, non-isomorphic pair yields `Hold`, never `Pass`.
5. **Window Bound**: no window with >8 nodes is scanned without a `WindowOverflowResidue`/Hold.
6. **Provenance**: every window carries source, position, time, adapter, authority, replay_ref — enforced at the type level (`trybuild` compile-fail proves a provenance-less window is unconstructible).
7. **Replay**: identical window + `RunDescriptor` ⇒ identical `MpkFieldSample`/atlas digest.
8. **Authority Boundary**: a capture-shaped source is refused with `UnauthorizedSurfaceSource`.
9. **Scalpel absence**: no rewrite/apply path exists (compile-fail test); scalpel work is explicitly *not* in this increment.
10. **Workspace gate green**: `fmt` + `build` + `test` + `clippy -D warnings` + `ssk-mpk --no-default-features` + `cargo deny` + `cargo audit`.

**Why this and not something else** (per the task's priority order):
1. *Produktionsnotwendigkeit* — every other FCHL-MPK component consumes `MpkFieldSample`/`Atlas`; nothing above it can exist first.
2. *Spezifikationskonformität* — directly achieves FCHL-MPK-0…2 plus the cospectral/catalog/boundary residue-gating of FCHL-MPK-4, with the Addendum's exact acceptance tests.
3. *Sicherheitsrelevanz* — read-only, no network, no OS, no privilege, no actuation; it adds zero attack surface and correctly gates the privileged bands behind itself.
4. *Testbarkeit* — fully unit/property/replay/compile-fail testable in isolation; the spec even supplies the test list.
5. *Integrationsrisiko* — new leaf crates, no edits to `ssk-runtime`/`ssk-daemon`/`ssk-netcore`; reuses proven primitives.
6. *Rückbaubarkeit* — additive and caller-less until explicitly wired; trivially removable.
7. *Replayfähigkeit* — replay-bound by construction (`ReplayGate` mandatory; reuses the genuinely-re-executing `ReplayEngine`).

**Explicitly gated for later, not silently claimed:** FieldTensorSkin/HostCellPlane/FunnelDAG/TFA/MetaResonance (Band B — need an authorized source), and TopologyScalpel *application* / BoundaryActuator / system-wide Kill-Switch / SystemTrafficField capture / ProfileManifold+CrownSupervisor full integration (Band C — privileged, `[SSCL-UNVERIFIED]`, require both the missing SSCL Produktions-Master-Spezifikation and explicit authorization before any actuation is built).

---

### One-line recommendation

Build **`ssk-mpk`** next, because it is the deterministic, non-privileged foundation the entire FCHL-MPK layer stands on and it reuses the SSK core's already-proven gate/residue/replay/content-address primitives at near-zero integration risk. It is accepted only when the ten tests above pass — the Addendum's mandatory MPK suite (Canon-idempotence, Orbit-Stabilizer, Complement-involution, Cospectral-Hold, Window-bound, Provenance, Replay, Authority-boundary) plus the green workspace gate — and it is explicitly **not** accepted as "the FCHL-MPK layer is done": Bands B and C, and every privileged/actuating capability, remain gated and unbuilt until separately authorized.
