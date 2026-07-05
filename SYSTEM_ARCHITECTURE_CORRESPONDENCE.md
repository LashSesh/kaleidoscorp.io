# System Architecture Correspondence — full corpus ↔ SSK codebase

> **IMPLEMENTATION STATUS (living).** Layers this correspondence marked "absent /
> greenfield" have since been built as green, tested, `clippy -D warnings`-clean
> crates on top of the proven Ω core:
> - **`ssk-netcore`** — the real network data plane (TCP/SOCKS5/TLS/DNS), closing SSKΩ-7.
> - **`ssk-signature`** — the Chameleon spectral substrate (spectrum-as-identity); the
>   `CanonicalTrafficSurface`/SignatureLab feed. 73 tests.
> - **`ssk-imdf`** — the Mirror Dome seed (IMDF-0..2): SelfAnchor≠Locator, authorized
>   ObserverModels, aperture-before-focus, QLOGIC gate, 4π-closure, hash-chained
>   SelfPerceptionAtlas. All 11 IMDF Appendix A tests. 13 tests.
> - **`ssk-capture`** — SSCL SystemTrafficField (SSCL-2), payload-neutral
>   CanonicalTrafficSurface with provenance + replay.
> - **`ssk-boundary`** — the session-local system-wide kill-switch (SSCL-7): policy +
>   hash-chained audit + rollback + authorized override.
> - **`ssk-mpk`** — the FCHL-MPK finite-symmetry core (Band A): Canon/Orbit/Stab/Spec/
>   Comp/Catalog + cospectral gate. FCHL-MPK invariants I3–I8 (incl. the Schwenk pair).
> - **`ssk-field-tensor`** — the FieldTensorSkin (FTCSA, Band B): F = T_surface + T_res +
>   C_coupling + δF, honestly typed as an observation surface.
> - **`ssk-meta-resonance`** — the MetaResonanceController (Band B): PID feedback that
>   stabilizes/delays but never bypasses a gate; no gate-flicker.
> - **`ssk-host-cells`** — the HostCellPlane (Heavenly Hosts, Band B): ephemeral,
>   capability/scope-bound role cells with TTL + dissolution; HostCell ≠ public identity.
> - **`ssk-funnel-dag`** — the FunnelDAG (FCHL sense, Band B): host-relation work DAG,
>   DAG-by-construction, TTL + hash-chained trace (temporal-window replay).
> - **`ssk-crown`** — the SSCL CrownSupervisor: the fail-closed emission gate that clamps
>   signature gate + IMDF QLOGIC + kill-switch + MetaResonance + open obligations into one
>   audited, replay-stable emission decision.
> - **`ssk-profile-manifold`** — the SSCL ProfileManifold: content-addressed profiles with a
>   substantive privacy-downgrade gate (transitions need control auth; downgrades need a
>   second use), hash-chained audit of applied *and* rejected transitions.
> - **`ssk-topology-scalpel`** — the FCHL-MPK Band B TopologyScalpel: candidate-only, gated,
>   reversible topology-edit plans (never mutates a live topology; rollback-that-doesn't-
>   restore → Reject; protected → Hold). 5 tests.
> - **`ssk-tfa`** — the FCHL-MPK Band B Transduction / Field-Amplitude adapter: bounded,
>   gated, candidate-only actuation from δF signals — no silent amplification (clamps and
>   deadband drops are recorded residues), privileged effects never auto-pass, an injected
>   Effector actuates only Pass candidates behind a hash-chained ledger. **Band B complete.**
> - **`ssk-service-host`** — the SSCL Crown ServiceHost: a fail-closed, authorization-gated,
>   audited lifecycle state machine (Uninstalled→Installed→Running→Stopped) with a capability
>   handshake and rollback-on-uninstall, driving an injected PrivilegedHelper seam.
> - **`ssk-delivery`** — the SSCL Crown DeliveryEnvelope: a content-addressed installable /
>   upgradable / removable unit + a candidate-only, gated, reversible migration planner
>   (minimal upgrade diff, exact rollback, protected-hold, reconstructible uninstall receipt).
> - **`ssk-system`** — the end-to-end composition: a `SystemPipeline` wiring capture →
>   field-tensor → transduction → signature gate → QLOGIC → MetaResonance → ServiceHost
>   health → CrownSupervisor into one fail-closed, replay-stable evaluation. 5 cross-crate
>   integration scenarios (each composing 10 real crates) prove the priority survives crate
>   boundaries and that no subsystem can promote a decision.
>
> Whole workspace: **40 crates, 398 tests green**, `clippy -D warnings` clean, `cargo deny`
> ok, `ssk-core` no_std intact. All four named capabilities are in. **Band B is complete**
> (field-tensor, MPK, meta-resonance, host-cells, funnel-dag, topology-scalpel, TFA) and the
> **SSCL Crown surface is in** (capture, boundary, profile-manifold, crown, service-host,
> delivery), composed end to end in `ssk-system`. Remaining greenfield (honest): binding the
> pure seams to **real privileged backends** (OS-level traffic capture, egress teardown, a
> real system service / installer for `ServiceHost`/`PrivilegedHelper` and `DeliveryEnvelope`);
> the **top rungs (…-9)** of each conformance ladder; and productization (signed release
> artifacts, durable on-disk audit stores, packaging binaries rather than source).

**Deliverable "A": the complete architecture correspondence across the whole normative corpus, mapped onto the existing `ssk-*` workspace.** This subsumes and extends `FCHL_MPK_INTEGRATION_STRATEGY.md` (which was FCHL-MPK-scoped) to all seven source documents, unifies their conformance ladders into one, and gives one integration sequence.

Every "exists" claim carries a `file:line`. Every normalization of an older/metaphorical term is taken verbatim from the two master specs' own mapping tables (SSCL ch. 2 Extraktionstabelle; FCHL-MPK Addendum Appendix B; IMDF ch. 2 + Quellenbindung), never invented. Boundaries in these documents are the author's own design decisions (configurable defaults), plus the lawful frame the author named — not agent-imposed limits (see `FCHL_MPK_INTEGRATION_STRATEGY.md` §1.3).

---

## 0. Corpus inventory (all present this session) and normative order

| # | Document | Form held | Own conformance ladder | Own crate blueprint | Repo status |
|---|---|---|---|---|---|
| 1 | **SSCL** System Surface Crown Produktions-Master (Ω+2) | full `.tex` | SSCL-0…9 | `sscl-*` (14 crates) | **partial** (daemon/netcore/config) |
| 2 | **FCHL-MPK** Architektur-Addendum | full `.tex` | FCHL-MPK-0…9 | `sscl-fchl-*` (11 crates) | **absent** (greenfield) |
| 3 | **SSKΩ** Kaleidoscorp Ω Rust Master Spec | PDF + `docs/OMEGA_CORE_CONFORMANCE_SPEC.md` | SSKΩ-0…9 | `ssk-*` (the workspace) | **partial→good** (the built core) |
| 4 | **IMDF-MD** Immersive Mirror Dome Field Layer | full PDF text | IMDF-0…9 | `imdf-*` (10 crates) | **absent** (greenfield) |
| 5 | **5D_Cube** Deterministic Blueprint + Meta-Resonance | full PDF text | acceptance tests (BI/replay) | — (a kernel, not a layer) | **substrate partially realized** (replay/determinism) |
| 6 | **FTCSA** | full PDF text (via 5D_Cube §4 + Addendum §3.1) | — | → FieldTensorSkin | **absent** |
| 7 | **Heavenly Hosts** | full PDF text (via 5D_Cube §4 + Addendum §3.2) | — | → HostCellPlane | **absent** |

**Normative order** (author-declared): SSCL ⟩ FCHL-MPK ⟩ SSKΩ ⟩ IMDF/Mirror-Dome ⟩ MERKABA/QLOGIC/BCIK/Replay ⟩ MPK ⟩ FTCSA/HeavenlyHosts/TFA ⟩ older. The two master specs (SSCL, FCHL-MPK) fix the production normal form; the four source docs (IMDF, 5D_Cube, FTCSA, Heavenly Hosts) are folded to their normalized roles where they collide.

---

## 1. The single shared kernel (the load-bearing insight)

**All five formal specs are the same discipline in different domains.** Each one, independently, mandates: content-addressed identity, a *multi-dimensional* gate that yields Pass/Hold/Fail (never a single score), typed residues with "no silent loss," a genuine replay, "Locator ≠ Identity," a BCIK-style gated crossing, and an append-only ledger. This is not coincidence — it is one kernel, and **the repo already implements it.** Every higher layer reuses it rather than re-deriving it.

| Kernel primitive | SSKΩ | IMDF | SSCL | FCHL-MPK | 5D_Cube | Already in repo (`file:line`) |
|---|---|---|---|---|---|---|
| Content-addressed id / canonical hash | `Digest`, `content_id!` | `Digest`, `replay_root` | `Digest`, `content_digest` | `canonical_hash` | `C_t=H(µ,Φ,β,Π,seed,vers)` | `crates/ssk-types/src/lib.rs:56` `Digest`, `:112` `content_id!` |
| Multi-dim gate → Pass/Hold/Fail(/Refine/Quarantine) | `GateVector`, `GateOutcomeKind` | `GateVector g=(κ,H,Π,R,B,Δ)`, Decision | `GateVector`, CrownSupervisorDecision | 12 MPK gates | `Gate` op + no-flicker | `ssk-types:637` `GateId`, `:784` `GateOutcomeKind`; `crates/ssk-gates/src/lib.rs:351` `GateVector` |
| Typed residue + **no silent loss** | `ResidueKind`, `BoundaryResidue.open_obligation` | Residue/ResidueCloud/Blindspot, Axiom 1.6 | `CrownResidueKind` (14) | 9 MPK residues, CounterHorizon | "was nicht integriert wird → Residuum" | `ssk-types:676` `ResidueKind`, `:691` `BoundaryResidue`, `:731` `ResidueRegister` |
| Genuine replay (re-execution, not archive) | `ReplayEngine`, `DeterminismContext` | ρ Replay, Reanalysis; `test_replay_manifest` | ReplayManifest, "Replay-Abnahme" | `ReplayGate` | "C_replay = C_t" | `crates/ssk-replay/src/lib.rs:25` `trait ReplayEngine`; `crates/ssk-runtime/src/lib.rs:423` `DeterminismContext` |
| Locator ≠ Identity | Identity/Locator planes | Invariante 4.2, Axiom 15.1 | (inherits SSKΩ) | HostCell ≠ public id | — | `crates/ssk-identity`, `crates/ssk-locator`; enforced in gate vector |
| BCIK gated crossing | `Bcik::cross` | ch. 15.3 `Cross(I,L)⇒BCIKWitness` | (inherits) | seam/boundary per window | Solve/Gate/Coagula | `crates/ssk-bcik/src/lib.rs`; used `crates/ssk-runtime/src/lib.rs:268-283` |
| Append-only hash-chained ledger | tensor + audit | Λ Ledger, "kein stiller Rewrite" | AuditLedger, append-only | SurfaceLedger | commit schema | `crates/ssk-netadmin/src/audit.rs` `AuditLedger` (now daemon-recorded); `crates/ssk-tensor` |
| Deterministic scheduler / meta-resonance | `HypertoroidalScheduler`, PID via `MetaResonance` | — | — | `MetaResonanceController` (+K_S s_t) | PID `u=K_Pe+K_IΣe+K_D∆e` around Mandorla | `crates/ssk-scheduler/src/lib.rs:40-87` |

**Consequence:** a new layer is *not* a new engine. It is a new domain vocabulary over this kernel. `ssk-types`/`ssk-gates`/`ssk-replay`/`ssk-crypto`/`ssk-tensor`/`ssk-audit` are the shared substrate every layer below depends on, and they are the strongest, best-tested part of the tree.

---

## 2. Unified layer stack

Canonical order, reconciled from SSCL's `Foundation ≺ Runtime ≺ Mirror Dome ≺ System Surface Crown ≺ Packaging/UI` and IMDF's `Foundation ≺ Runtime ≺ Product ≺ Workbench ≺ Domain`:

```
L7  Packaging / UI            DeliveryEnvelope, ssk-cli, (ssk-desktop)          [SSCL ch.9 · partial/absent]
L6  System Surface Crown      SSCL: SystemTrafficField · ServiceHost ·          [SSCL-0..9 · PARTIAL]
     (+ FCHL-MPK addendum      ProfileManifold · BoundaryActuator/KillSwitch ·
      plane couples in here)   CrownSupervisor · DeliveryEnvelope
                               FCHL: FieldTensorSkin · HostCellPlane · FunnelDAG ·[FCHL-MPK-0..9 · ABSENT]
                               MPK · TFA · MetaResonance · TopologyScalpel
L5  Mirror Dome               IMDF: SelfObservationField · ObserverModels ·      [IMDF-0..9 · ABSENT]
                               Aperture/Lens/Split/Parallax · Wavefront ·
                               QLOGIC · 4π-Closure · SelfPerceptionAtlas · Reanalysis
L4  Runtime (Ω)               ssk-runtime · run_to_outcome · scheduler ·          [SSKΩ-1,6 · GOOD]
                               focus · replay · netcore (real egress) · daemon
L3  Decision core (Ω)         ssk-core/locator/bcik/gates/stitch/tensor/         [SSKΩ-0..5 · GOOD/partial]
                               identity/privacy/config · 12-gate vector
L2  Meta-resonance substrate  5D_Cube: Solve/Gate/Coagula · Mandorla · BI ·      [5D · PARTIAL as determinism]
                               replay-commit · Meta-Resonanz(FTCSA⊗Hosts) PID
L1  Foundation                ssk-types · ssk-crypto (Digest/content_id/gate/    [SSKΩ-0 · GOOD]
                               residue/replay primitives — the shared kernel §1)
```

Two source docs are **inputs**, not layers: **FTCSA** supplies the constraint tensor `T` that becomes `FieldTensorSkin` (`F = T_surface + T_res + C_coupling + δF`, Addendum §3.1; the "tensorielle Strukturspannung/Constraint" of 5D_Cube §4.1); **Heavenly Hosts** supplies the exploration impulses `R` that become `HostCellPlane` (`HostCell=(role,epoch,capability,localView,coherence,ttl,trace)`, Addendum §3.2; the "nichtlokale Resonanz-Impulse/Exploration" of 5D_Cube §4.1). Their coupling **is** the 5D_Cube Meta-Resonance layer (`∆T=α_TΠ_sym+(R−R^eq)`, `∆R=−α_R(R−G(T))`).

### Crate mapping (source blueprint → workspace `ssk-*` name) [design-decision: one `ssk-` prefix]

| Source crate(s) | Workspace crate | Status |
|---|---|---|
| `imdf-core/observer/aperture/wavefront/qlogic/residue/ledger/adapters/cli` | `ssk-imdf-*` (or fold observer/aperture into `ssk-imdf`) | NEW |
| `sscl-capture(-local)` | `ssk-capture` | NEW (the SystemTrafficField the user wants) |
| `sscl-profile` | extend `ssk-config` + new `ssk-profile` | EXTEND/NEW |
| `sscl-killswitch` / BoundaryActuator | `ssk-boundary` | NEW |
| `sscl-service` / ServiceHost + PrivilegedHelper | `ssk-service` | NEW |
| `sscl-package` / DeliveryEnvelope | `ssk-package` | NEW |
| `sscl-supervisor` / CrownSupervisor | extend `ssk-daemon` (already the partial supervisor) | EXTEND |
| `sscl-mirror-feed` | `ssk-imdf-feed` (DomeFeed bridge) | NEW |
| `sscl-fchl-types/mpk-bridge/graph-windows/topology-atlas/topology-scalpel/field-tensor/host-cells/funnel-dag/tfa` | `ssk-fchl-*`, `ssk-mpk`, … (per `FCHL_MPK_INTEGRATION_STRATEGY.md` §6) | NEW |
| `sscl-audit/replay`, `imdf-ledger`, MPK replay | **reuse** `ssk-audit` / `ssk-replay` / `ssk-tensor` | REUSE |
| `sscl-types`, `imdf-core` foundation | **reuse/extend** `ssk-types` | REUSE/EXTEND |

---

## 3. Unified conformance ladder (four ladders, one table)

Each column is that spec's own rung text (condensed); the **Repo** cell is the honest current state with evidence. `✓`=met, `◑`=partial, `✗`=absent.

| n | SSKΩ-n (Ω core) | IMDF-n (Mirror Dome) | SSCL-n (Crown) | FCHL-MPK-n (addendum) | Repo today |
|---|---|---|---|---|---|
| 0 | typed model; core/identity/locator typed | SelfAnchor exists, ≠ Locator | typed baseline: Profile/ServiceState/CaptureMode/AuditEvent | terms/boundaries/data-contracts | **SSKΩ-0 ✓** (`ssk-types`, no_std fixed); others ✗ |
| 1 | deterministic core + scheduler | ObserverModels typed + apertured | config parser + validation, positive-only rejected | WindowExtraction w/ provenance+replay | **SSKΩ-1 ✓**; SSCL-1 ◑ (`ssk-config` validates; profiles hardcoded); IMDF/FCHL ✗ |
| 2 | mirror orbit + locator reality check | aperture-before-focus enforced | SystemTrafficField from passive local sources | MPK orbit/canon/stab/spec/catalog | **SSKΩ-2 ◑**; SSCL-2 ✗ (capture unbuilt — user-wanted); IMDF/FCHL ✗ |
| 3 | BCIK candidate pipeline | Split/Parallax + residues | ProfileManifold, versioned + gated transitions | SymmetryAtlas aggregation | **SSKΩ-3 ✓**; others ✗/◑ |
| 4 | 12-gate vector + residues | ImmersionField + FieldCells | Mirror-Dome feed from CTS + linkability | cospectral/boundary/out-of-catalog gated Holds | **SSKΩ-4 ✓**; SSCL-4 needs IMDF; others ✗ |
| 5 | persistent tensor + audit | wavefront from ≥2 perspectives | ServiceHost, visible status, least-privilege | HostCellPlane/FunnelDAG projections | **SSKΩ-5 ◑** (in-mem real; durable partial); others ✗ |
| 6 | focus + replay | QState + GateVector multi-dim | BoundaryActuator dry-run + rollback + gates | FieldTensorSkin couples field↔windows | **SSKΩ-6 ✓**; others ✗ |
| 7 | **real egress adapters + health probing** | 4π-closure for orientation-relevant runs | **system-wide kill-switch** w/ policy/audit/rollback/override | TFA + MetaResonance MPK feedback | **SSKΩ-7 ◑→✓** (`ssk-netcore` real egress built); SSCL-7 ✗; others ✗ |
| 8 | simulation + conformance testbed | Replay + Reanalysis on SelfAnchor | DeliveryEnvelope: packaging + migration + uninstall | TopologyScalpel gated rollback plans (candidate) | **SSKΩ-8 ✓** (in-process); SSCL-8 ✗ (ships source not binaries); others ✗ |
| 9 | production-hardened profile | SelfPerceptionAtlas auditably committed | full CrownSupervisor pipeline + replay + faultscan | full SSCL production integration | all **◑/✗** — the top rung of every ladder is open |

**5D_Cube overlay** (applies to every layer's acceptance): BI monotone (`BI_{t+1}≥BI_t−ε`), convergence (`∆W↓, ∆F≤0`), **gate-persistence / no flicker**, replay-equality (`C_replay=C_t`). The repo satisfies replay-equality (`ssk-replay`) and determinism; BI and no-flicker are new acceptance metrics to add per layer.

**Headline:** the Ω core (L1–L4) is genuinely strong (SSKΩ-0,1,3,4,6,8 met; 2,5 partial; 7 now real via `ssk-netcore`). Everything above it — IMDF (L5), the SSCL Crown parts beyond the daemon skeleton (L6), and the entire FCHL-MPK plane — is greenfield. Every top rung (n=9) is open.

---

## 4. Spec-to-code crosswalk (major objects, whole corpus)

`REUSE`=existing type usable · `EXTEND`=existing pattern + new variant · `NEW`=greenfield · legend as §1.

| Object (source) | Production role | `ssk-*` location / target | Status |
|---|---|---|---|
| `SelfAnchor=(id,scope,owner,policy,keyctx,replayRoot,boundary)` (IMDF 4.1) | canonical own-identity | `ssk-types` `CoreNode`/identity + new `SelfAnchor` | EXTEND |
| `ObserverModel=(id,scope,vantage,aperture,lens,blindspots,trust,replay)` (IMDF 5.1) | authorized self-perspective | `ssk-imdf` | NEW |
| Aperture-before-Focus (IMDF 6.1, `Focus⇒∃A`) | typed measurement bound | `ssk-imdf` typestate | NEW |
| `BirefringentSplit`/`Parallax` (IMDF 7) | multi-perspective anti-false-uniqueness | `ssk-imdf` | NEW |
| QLOGIC `g=(κ,H,Π,R,B,Δ)` → Pass/Hold/Fail (IMDF 10) | 6-dim gate vector | pattern of `ssk-gates` `GateVector`; new `ssk-imdf` gate | EXTEND |
| `4π-Closure` (IMDF 11) | orientation-return check (2π≠enough) | `ssk-imdf` | NEW |
| `SelfPerceptionAtlas` (IMDF 13) | main artifact, hash-chained | `ssk-imdf` + reuse `ssk-audit`/`ssk-replay` | NEW+REUSE |
| `SystemTrafficField=(Sources,Samples,Scope,…)` (SSCL 4) | authorized local capture | `ssk-capture` (`CaptureMode`/`CaptureScope`/`CaptureAdapter::dry_run`) | NEW |
| `CanonicalTrafficSurface` (SSCL 5) | payload-neutral surface, feeds Dome | `ssk-capture` + `ssk-imdf-feed` | NEW |
| `ProfileManifold` / `SystemProfile` (SSCL 6) | versioned policy bodies + resolver | extend `ssk-config` + `ssk-profile` | EXTEND/NEW |
| `CrownSupervisor` → {Pass,Hold,Fail,Quarantine,Engage,Disengage,Rollback} (SSCL 7) | gated emission orchestrator | extend `ssk-daemon` `Supervisor`/`DaemonState` (`crates/ssk-daemon/src/supervisor.rs`) | EXTEND |
| `BoundaryActuator` + `KillSwitchState` (SSCL 8) | actuator: session egress **or** OS firewall, rollback-before-engage | `ssk-boundary`; today per-session teardown exists (`ssk-daemon` `Deactivate`) | EXTEND/NEW |
| `ServiceHost` + `PrivilegedHelper` (SSCL 9) | OS-service lifecycle, least-privilege | `ssk-service`; today single `sskd` bin (`crates/ssk-daemon/src/main.rs`) | EXTEND/NEW |
| `DeliveryEnvelope` (SSCL 10) | packaging + signatures + uninstall | `ssk-package`; today release ships source (`.github/workflows/release.yml`) | NEW |
| MPK apparatus / `MPKFieldSample` / `TopologySymmetryAtlas` (Addendum 4-6) | finite symmetry over n≤8 windows | `ssk-mpk` / `ssk-topology-atlas` | NEW |
| `FieldTensorSkin` `F=T_surf+T_res+C_coupling+δF` (FTCSA / Addendum §3.1) | observation surface (not physics) | `ssk-field-tensor` | NEW |
| `HostCellPlane`/`FunnelDAG` (Heavenly Hosts / Addendum §3.2) | ephemeral role cells, TTL, dissolution | `ssk-host-cells`/`ssk-funnel-dag`; reuse `DissolutionManager` | NEW+REUSE |
| `MetaResonanceController` PID `u=K_Pe+K_IΣe+K_D∆e(+K_S s_t)` (5D_Cube §4 / Addendum 6) | field↔symmetry feedback, no gate bypass | `ssk-meta-resonance`; reuse scheduler PID pattern | NEW |
| `Bündigkeitsindex` BI (5D_Cube §2.4, Addendum 6) | acceptance metric (monotone, no flicker) | new acceptance metric across layers | NEW |
| `TopologyScalpel`/`ScalpelPlan{status}` (Addendum 9) | gated rewrite **candidate** (no auto-apply until BoundaryActuator) | `ssk-topology-scalpel` | NEW |

---

## 5. Gap matrix (whole corpus)

| Layer / component | Expected (spec) | Repo state (`file:line`) | Gap → measure |
|---|---|---|---|
| Shared kernel L1–L2 | content-id/gate/residue/replay/scheduler | **real & tested** (`ssk-types`,`ssk-gates`,`ssk-replay`,`ssk-scheduler`, `ssk-netadmin/src/audit.rs`) | none → reuse everywhere |
| Ω core L3–L4 | SSKΩ-0..9 | 0,1,3,4,6,8 ✓; 2,5 ◑; 7 now ✓ egress (`ssk-netcore`) | harden 2 (locator liveness), 5 (durable persistence) |
| **SystemTrafficField** (SSCL-2) | passive local capture, metadata-first | **absent**; `ListRecentFlows→[]` (`crates/ssk-daemon/src/supervisor.rs`) | **NEW `ssk-capture`** (user-named priority) |
| **Mirror Dome** (IMDF-0..9) | self-perception atlas over observers | **absent** (greenfield) | **NEW `ssk-imdf`**, reuses Ω identity/gate/replay |
| ProfileManifold (SSCL-3) | multi-profile, gated transitions | **absent**; one hardcoded reference profile (`supervisor.rs` `reference_policy_engine`) | extend `ssk-config`, new `ssk-profile` |
| BoundaryActuator / KillSwitch (SSCL-6/7) | session **or** OS-firewall, rollback-before-engage, honest scope | per-session teardown only; `kill_switch=false` (`supervisor.rs`) | **NEW `ssk-boundary`** |
| ServiceHost / DeliveryEnvelope (SSCL-5/8) | OS service + packaging + uninstall | single `sskd` bin; release ships source | `ssk-service`, `ssk-package` |
| FCHL-MPK plane (FCHL-MPK-0..9) | field/host/MPK/TFA/scalpel | **absent** (greenfield) | per `FCHL_MPK_INTEGRATION_STRATEGY.md` |
| 5D_Cube substrate | Solve/Gate/Coagula + BI + Mandorla | determinism/replay realized; BI/Mandorla/PID absent | `ssk-meta-resonance` + BI metric |
| CrownSupervisor (SSCL-9) | gated emission over all side-effects | **partial**: `ssk-daemon` `Supervisor`+`DaemonState` real | extend, don't duplicate |

---

## 6. Target topology & unified integration sequence

The three specs' own sequences interleave cleanly because they share the kernel. One ordering that respects every dependency (each block ends green on the kernel gate: `fmt+build+test+clippy+no_std+deny+audit`, plus the layer's own acceptance tests):

- **Block Ω′ (harden the base you have)** — SSKΩ-2 locator liveness (real probe already exists in `ssk-netcore`), SSKΩ-5 durable stitch-chain `verify()` + file-backed tensor on a product path. Small, closes two known partials.
- **Block M (Mirror Dome seed, IMDF-0..2)** — `ssk-imdf`: `SelfAnchor`(≠Locator), typed `ObserverModel`, aperture-before-focus (typestate), local/synthetic adapters only, RunDescriptor+ReplayManifest+GateReport. Pure, local, reuses Ω identity/gate/replay. IMDF Appendix A gives the exact acceptance tests.
- **Block C (SystemTrafficField, SSCL-2)** — `ssk-capture`: `CaptureMode`/`CaptureScope`/`CaptureAdapter::dry_run`, passive tier first (route table, interface counters, DNS/proxy/socket state), then feature-gated privileged packet-metadata. This is the user-named capability; it also feeds M and the FCHL field layer.
- **Block P (ProfileManifold, SSCL-3)** — thread validated config into a real multi-profile model driving the daemon (retire the hardcoded reference policy).
- **Block MPK (FCHL-MPK-0..2+4, `ssk-mpk`)** — the deterministic finite-symmetry core with `IdentityPolicy` (incl. `SpectrumOnly` → labeled `SpectralClass`), over safe in-repo graph sources; see `FCHL_MPK_INTEGRATION_STRATEGY.md` §10.
- **Block F (Field/Host coupling, FCHL-MPK-5/6 + FTCSA + HeavenlyHosts + 5D_Cube)** — `ssk-field-tensor`, `ssk-host-cells`, `ssk-funnel-dag`, `ssk-meta-resonance` (PID + BI). Consumes C's capture as the field source.
- **Block B (BoundaryActuator, SSCL-6/7)** — `ssk-boundary`: full `KillSwitchState`, dry-run + rollback-before-engage, session and OS-firewall reach, honest scope reporting. Privileged; wants dry-run + rollback tests.
- **Block S/D (ServiceHost + DeliveryEnvelope, SSCL-5/8)** — `ssk-service`, `ssk-package`: OS-service lifecycle, least-privilege split, packaging with uninstall contract (fix release to ship binaries).
- **Block X (Crown + Scalpel + Atlas top rungs, SSCL-9/IMDF-9/FCHL-MPK-9)** — extend `ssk-daemon` into the full `CrownSupervisor` emission gate; `ssk-topology-scalpel` (candidate-only until B lands); SelfPerceptionAtlas + SymmetryAtlas committed to the shared ledger.

**Error flow (all layers):** any gate ≠ Pass → typed residue (`open_obligation`) → `ResidueRegister`/CounterHorizon (never deleted) → emission downgraded to Hold/Fail; hard fault → `Err` before any persistence (fail-closed, mirrors `run_to_outcome` `crates/ssk-runtime/src/lib.rs:251-264`). **Audit flow:** every layer appends to the hash-chained ledger (`ssk-netadmin/src/audit.rs`, now daemon-recorded); replay reproduces the report digest.

---

## 7. Recommendation / next action

Three builds are each defensible as "next," and this is genuinely the architect's call. Scored on the author's own priority order (production-necessity, spec-conformance, security, testability, integration-risk, reversibility, replay):

| Candidate | Prod-necessity | Conformance | Security surface | Test/replay | Integration risk | Verdict |
|---|---|---|---|---|---|---|
| **M — `ssk-imdf` (IMDF-0..2)** | high (next canonical layer above the built core) | IMDF-0..2, exact tests in IMDF Appendix A | none (local/synthetic, read-only) | excellent (pure, replay-bound) | minimal (reuses Ω identity/gate/replay; leaf crate) | **recommended first** |
| **C — `ssk-capture` (SSCL-2)** | highest (user-named; unblocks M & F) | SSCL-2 | low, passive/metadata (route/iface/DNS/proxy) — but touches OS surfaces | good (dry-run-first is testable) | low–med (OS adapters behind traits) | recommended second (or first if capture is the priority) |
| **MPK — `ssk-mpk` (FCHL-MPK-0..2)** | medium (addendum plane) | FCHL-MPK-0..2+4 | none | excellent | minimal | strong, but the addendum plane sits above C/F |

**Recommendation: build `ssk-imdf` (Mirror Dome seed, IMDF-0..2) next, because** it is the next layer in the author's own canonical order (Foundation ≺ Runtime ≺ **Mirror Dome** ≺ Crown), it reuses the existing, proven Ω kernel (`SelfAnchor`←identity, QLOGIC gate←`GateVector`, Replay/Reanalysis←`ReplayEngine`, BCIK←`ssk-bcik`, Locator≠Identity←existing) at near-zero integration risk, it is read-only/local (no privilege, nothing to gate externally), and IMDF Appendix A hands us the exact acceptance suite. It also produces the `SelfPerceptionAtlas` that the SSCL Crown's Mirror-Dome feed (SSCL-4) and the FCHL field layer both consume.

**Accepted only when** (IMDF ch. 21 + Appendix A, plus the workspace gate): `self_anchor_is_not_locator`, `aperture_before_focus_required`, `hidden_surface_becomes_residue`, `observer_without_authorization_fails`, `split_parallax_detects_inconsistent_views`, `gate_vector_is_not_single_score`, `replay_manifest_contains_all_inputs`, `reanalysis_recovers_self_anchor`, `blindspot_is_not_reported_as_fact`, `audit_ledger_is_append_only`, `four_pi_requires_second_orientation_pass` — plus `fmt+build+test+clippy -D warnings + ssk-imdf --no-default-features + cargo deny + cargo audit` green.

**If instead the priority is the capability you named** (SystemTrafficField capture), build **`ssk-capture` (SSCL-2)** first — passive/metadata tier, `dry_run`-first, feeding both the Mirror Dome and the FCHL field layer. Both are correct; M is the lowest-risk canonical-order step, C is the highest product-value step.

**Not claimed done:** every top rung (n=9) across all four ladders remains open; the FCHL-MPK plane, BoundaryActuator, ServiceHost/packaging, and the full CrownSupervisor are later blocks. This document is the map, not the territory.
