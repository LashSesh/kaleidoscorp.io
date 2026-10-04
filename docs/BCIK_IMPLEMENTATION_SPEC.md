# BCIK Implementation Specification

> **Provenance & method.** Derived from two monographs external to this repository, both authored
> by the repo owner and neither committed here (see Anhang F):
>
> - **`RDA`** — *"Rahmenwerk dualer Attraktorgeometrien"*, Band 0, Version 1.0, 2026 (121 pages) —
>   the parent metacalculus: a Grothendieck site, presheaves, holographic sheafification, a
>   reflective adjunction `L ⊣ J`, a mirror involution `Ψ`, the canonical triple separation
>   *intrinsic marker ≠ extrinsic claim ≠ observer-side image*, 4π-closure, a 12-step `RDA-CLOSE`
>   algorithm, 15 proof obligations, 15 negative tests, conformance levels RDA-0..RDA-6, and its own
>   Anhang D reserving the pattern for embedding other frameworks as conservative profiles.
> - **`BCIK`** (cited below as "the monograph") — *"Boundary-Closed Invariant Kernels"*,
>   Monographie v1.0, 2026 (54 pages) — the operative formal object, sharing its name with this
>   repo's existing `ssk-bcik` crate. Defines the typed tuple `K`, 8 axioms (A1–A8), a 9-gate
>   family, a small-step operational machine with a type system (subject-reduction + progress
>   proofs), a 5-stage refinement pipeline, 10 Verification Conditions (VC1–VC10), and a literal
>   Anhang B *"Anschlusslandkarte: vom Kern zur Software"* mapping every abstract concept to a
>   software counterpart.
>
> Every claim about *current* repository state below carries a `file:line` citation, verified by
> direct read on 2026-08-04 (not by subagent paraphrase — where a prior session pass reported a
> finding, it was independently re-read here before being restated). Every claim about the *target*
> model is either a direct, marked quotation from one of the two monographs, or explicitly labeled
> as this document's own instantiation choice. The two are never blended without a marker.
>
> **This is a specification, not implemented change.** No `.rs`, `.toml`, or other source file was
> written or modified to produce this document — confirmed by `git status --short` at the end of
> this pass. Every "task" implied below is a proposed obligation for a future implementation pass.
>
> **Status snapshot, not a permanent claim.** Mirroring `docs/IMRT_IMPLEMENTATION_SPEC.md`'s own
> practice: this document is versioned by the verification pass that produced it, not by wall-clock
> date. Where that document's own top-level roll-up table has already drifted from its own
> `§5a Resolution Log` (its own explicit warning, `IMRT_IMPLEMENTATION_SPEC.md:50-53`), this
> document corrects the affected rows rather than repeating the stale ones — see Teil VI.

## Abgrenzung

This document is not physics, not a roadmap, and not an implementation. It does not claim the
Riemann Hypothesis, Hilbert–Pólya, or any physical spin structure — the monograph's own Axiom A8
(Claim-Grenze) forbids exactly this, and this document inherits that restriction without
exception. It is also not scoped to per-app traffic steering alone: per the decisions recorded
below, BCIK is modeled here as the system's closure spine, with per-app attribution specified as
its first deferred consumer (Teil V), not its subject.

## Statusdisziplin

The monograph's own status classes are the primary label set used throughout, since the target
object being modeled is the monograph's:

| Class | Meaning |
|---|---|
| **D1** | definitorisch gesichert — true by definition |
| **D2** | beweisbar — provable from standard mathematics or the stated axioms |
| **D3** | Forschungsprogramm — structurally admissible, not proven as a theorem |
| **D4** | heuristische Motivation — not part of the hard core |

Where RDA is cited directly (Teil I's embedding argument), its own parallel status labels
(Definition / Axiom / Prinzip / Konstruktion / Lemma / Satz / Korollar / Hypothese /
Implementierungsvertrag / Forschungsfrage) are used and named as RDA's, not folded into D1–D4.

This document adds one verdict of its own, needed nowhere in either monograph because neither
describes an existing codebase: **Realized-but-Dead** — an invariant that is genuinely,
correctly enforced by real code, with real tests, and that no production entry point ever calls.

## Leseschlüssel

Teil I fixes where BCIK sits relative to RDA, IMRT, and SSKΩ, and resolves the crate/type naming
collision. Teil II is the monograph's hard core, quoted precisely. Teil III and IV instantiate the
two layers in scope (Pi-Seam, Gridlock) against this codebase; the other two monograph layers
(PZBA, Prime Boundary Atomics) are explicitly out of scope and named as such, not silently omitted.
Teil V specifies the deferred per-app consumer. Teil VI is the conservative-embedding profile —
the evidence table. Teil VII names the mechanism that prevents this model from becoming a fourth
instance of "built, tested, never called." Teil VIII gives proof obligations, negative tests, and
conformance grading. The appendices carry the symbol register, the full crosswalk, and sources.

---

# Teil I — Verortung

## 1. RDA as the parent metacalculus; BCIK as a conservative Sektion

RDA's own admission criterion for a Sektion, quoted exactly:

> **Definition 3.3 (Konservativer Morphismus).** Ein Morphismus `f: X → Y` heißt konservativ, wenn
> für jede Aussage `φ` in der Sprache von `X` gilt `Y ⊨ f(φ) ⟹ X ⊨ φ`. Äquivalent kann eine
> Rückprojektion `r: Y → X` mit `r ∘ f = id_X` verlangt werden.
>
> **Proposition 3.4 (Retraktion impliziert Konservativität).** Besitzt `f: X → Y` eine
> strukturtreue Retraktion `r: Y → X` mit `r ∘ f = id_X`, so ist `f` konservativ bezüglich aller von
> `r` erhaltenen Formeln.

The monograph's own H/F-instance split and typed Import-Gate (Teil II §8 below) are structurally
identical in shape to RDA's `L ⊣ J` reflective adjunction (RDA Axiom 8.1: the inclusion
`J: Closed ↪ Cand` has a left adjoint `L: Cand → Closed`, `L ⊣ J`) — the H-instance is RDA's
`Closed`, the F-instance is RDA's `Cand`, and the Import-Gate is RDA's reflector `L`. A retraction
`r` exists trivially: forget which crossing site `U` a `K(U)` was instantiated over, and the
monograph's tuple collapses back into a fiber of RDA's own `D`-tuple. By Proposition 3.4, **BCIK
embeds conservatively into RDA** — this is not asserted by analogy, it is the direct consequence of
the retraction existing. BCIK is therefore modeled here as **Band 1 (Sektion) of the RDA corpus**,
not a competing or freestanding framework.

## 2. Reconciling IMRT, SSKΩ, RDA, and the monograph's own A1–A8

Stated plainly, closing an issue that recurred across this session's earlier planning passes as
"three competing axiom systems": there is no competition once the objects are placed correctly.

| System | What it actually is | Disposition here |
|---|---|---|
| **RDA A1–A12 / I1–I12** | The metacalculus | **Normative parent.** |
| **IMRT A1–A10** (`docs/IMRT_IMPLEMENTATION_SPEC.md`) | A domain refinement of a mirror/self-perception layer | **Embeds conservatively** into RDA in most rows (Teil VI); one row (IMRT A1's `Z`) is a **Deformation**, not a Synthese — named plainly, not softened. |
| **SSKΩ-0..9** (`docs/OMEGA_CORE_CONFORMANCE_SPEC.md`) | A staged **conformance ladder** for this codebase's own release maturity | **Not an axiom set.** Structurally the same kind of object as RDA's own RDA-0..RDA-6 ladder — a release grading, not a competing set of normative statements. |
| **BCIK A1–A8** (the monograph) | The operative axioms for the closure object modeled and eventually built | **Operative going forward.** Everything built under this spec is checked against these eight, not against IMRT's or a separately-invented set. |

Two worked rows demonstrate the pattern, both verified against the actual monograph/RDA text and
the actual `ssk-imdf` source, in Teil VI in full; summarized here to close the reconciliation
question before the rest of the document proceeds:

- **IMRT A7 (4π-closure) embeds conservatively into RDA Def 7.5.** IMRT's own Satz 12.4 second
  conjunct (`[S]_can` preservation across the return) is *strictly stronger* than RDA's bare
  `γ̃(4π) = γ̃(0)`; forgetting that conjunct is the retraction. Genuinely conservative.
- **IMRT A1 (`Z` orders `S`) embeds into RDA's Axiom A5 (`N_int ≇ Z_∂`) as a Deformation, not a
  Synthese.** `ssk_imdf::self_anchor::NullAnchor` (`crates/ssk-imdf/src/self_anchor.rs:110-171`,
  read in full for this document) genuinely discharges *both* of RDA's separated roles in one type:
  it is structurally non-`Serialize` (RDA's `Z_∂` — "nicht bewohnbar", never crosses a boundary,
  confirmed: no `#[derive(..Serialize..)]` on the `NullAnchor` struct, contrasted directly against
  `SelfAnchor`/`DomeLocator`/`BcikCrossing` in the same file, which all do derive it) **and** it
  orders a `SelfAnchor` via `NullAnchor::order` (`self_anchor.rs:154-170`) — RDA's `N_int`
  ("`Coupling(N_int) > 0`", a coupling-active fixpoint). RDA Prinzip 19.3 names an embedding that
  destroys a declared invariant a *Deformation*, not a *Synthese* — this row is exactly that, and
  Teil VI states it as a required breaking change, not optional cleanup.

## 3. Namensdisziplin

Four identifiers in this codebase currently carry "Bcik", none of them yet instantiating the
monograph's object:

| Identifier | Location | What it actually is |
|---|---|---|
| `ssk_bcik::Bcik` | `crates/ssk-bcik/src/lib.rs:30-36` | The crossing kernel struct — three empty, `_`-prefixed placeholder fields plus a residue register; see Teil VI for its full, verified defects. |
| `GateId::Bcik` | `crates/ssk-types/src/lib.rs:641` (confirmed by direct grep) | One variant of the 12-member fail-closed gate enum. |
| `ssk_gates::BcikGate` | `crates/ssk-gates/src/lib.rs:150-178` (confirmed by direct grep) | A `Gate` impl whose own doc comment (line 150) already says "BcikGate: seam, boundary, residual projector, no silent crossing." |
| `ssk_imdf::self_anchor::BcikCrossing` | `crates/ssk-imdf/src/self_anchor.rs:212-243` (read in full) | A *second, unrelated* witness type: `{anchor: SelfAnchorId, locator: LocatorAddressId, witness: Digest}`, recording a crossing without equating ids — the right instinct, not an equalizer, and dead code (no production caller). |

**Resolution: keep all four names; do not rename or invent a numbered ladder the monograph does not
define.** Grade the crate itself against the monograph's own H/F-instance discipline (Teil II §8):
today's `ssk-bcik` is F-shaped work — untested against real invariants, closing on two booleans —
wearing an H-shaped name. The conformance grading in Teil VIII states this precisely once the
monograph's own vocabulary has been introduced, rather than inventing "BCIK-0..6" here.

---

# Teil II — Der harte Kern

Quoted directly from the monograph, verbatim, so that later Teile can cite specific clauses without
re-deriving them.

## 4. The typed tuple

> **Definition 5.1 (Getypter Kern).** Ein Kern-Kandidat ist ein getyptes Tupel
> `K = (X, Σ, T, Can, R, B, B⁻, G, τ, ρ, Π, Replay, PathInv)`, mit Zustandsraum `X`, Boundary `Σ`,
> Transformationsoperator `T`, Kanonisierung `Can`, Reflexion `R = R*, R² = I` und Projektoren
> `B = ½(I+R)`, `B⁻ = ½(I−R)`, Gate-Familie `G`, Trace `τ`, Residualoperator `ρ`,
> Materialisierungsabbildung `Π`, Replay-Prädikat `Replay` und Pfadinvarianz `PathInv`.
>
> **Definition 5.2 (Umgestülpte Boundary).** Die operative Boundary eines Kerns wird als
> abgeschlossener Horizont `H_Σ` mit nichtleerem Inneren `Int(H⁻_Σ)` modelliert. Ein Zustand sitzt
> in der Boundary, wenn er in diesem Inneren liegt; `H⁻_Σ` bezeichnet die zur Reflexion `R`
> gehörige Residualseite.

## 5. The eight axioms

> **Axiom 6.1 (A1–A8).**
> A1 Kanonisierung: `Can² = Can` (idempotent, deterministisch).
> A2 Signatur: `σ = σ ∘ Can`. Ist `σ` unvollständig, wird jede Kollision als Residuum protokolliert.
> A3 Boundary-Existenz: `BCIK(K) = 1 ⟹ Int(H⁻_Σ)(K) ≠ ∅`.
> A4 Closure-Pflicht: `Closed(K) = 1` ist Pflicht; ein Residualpol darf nicht still absorbiert werden.
> A5 Fail-closed Gate: `¬Pass(G)(K) ⟹ Materialize(K) = 0`. Bei Unsicherheit gilt Hold, nicht Fire.
> A6 Trace und Replay: `Materialize(K) = 1 ⟹ τ(K) ∧ Replay(K)`.
> A7 Pfadinvarianz: `γ₁ ∼ γ₂ ⟹ Can(K_γ1) = Can(K_γ2)`.
> A8 Claim-Grenze: Der Kern behauptet keine Physik, keine RH, keine Hilbert-Pólya-Struktur und
> keine metaphysische Ontologie. Domänenaussagen sind Projektionen.

Note the monograph's own A5 is a **fail-closed gate axiom**, distinct from RDA's A5
(`N_int ≇ Z_∂`, the dual null-separation axiom). The two share a number by coincidence of separate
authorship contexts; this document always disambiguates by system name (**RDA A5** vs. **BCIK A5**)
and never bare "A5".

## 6. The gate family

> **Definition 7.1 (Gate-Familie).** Die Kern-Gate-Familie ist die Konjunktion
> `G = G_typed ∧ G_boundary ∧ G_closure ∧ G_residue ∧ G_evidence ∧ G_trace ∧ G_replay ∧ G_path ∧ G_scope`.

| Gate | Bedeutung |
|---|---|
| `G_typed` | Alle Objekte besitzen Typ, Rolle und Lebenszyklus. |
| `G_boundary` | Eine operative Boundary `Int(H⁻_Σ)` existiert. |
| `G_closure` | Closure ist erreicht; offene Residuen verhindern Materialisierung. |
| `G_residue` | Residuen sind sichtbar, nicht absorbiert. |
| `G_evidence` | Evidence ist content-addressed bzw. eindeutig referenzierbar. |
| `G_trace` | Der Ableitungspfad ist protokolliert. |
| `G_replay` | Gleicher RunDescriptor erzeugt dieselbe kanonische Klasse. |
| `G_path` | Zulässige Pfadvariation erzeugt dieselbe kanonische Klasse. |
| `G_scope` | Keine unzulässige Domänenüberbehauptung. |

## 7. The central law

> **Definition 9.1 (Boundary-Closed Invariant Kernel).** Ein Kern-Kandidat `K` ist ein
> Boundary-Closed Invariant Kernel, wenn
> `BCIK(K) = 1 ⟺ K ∈ Fix(T) ∩ Int(H⁻_Σ) ∩ Closed ∩ Pass(G) ∩ τ ∩ Replay ∩ PathInv`.
>
> **Satz 9.2 (Materialisierbarkeit).** Ein Kandidat `K` materialisiert genau dann, wenn
> `BCIK(K) = 1` und `cert(K) ≠ ∅`. Insbesondere folgt aus `¬Pass(G)(K)` sofort `Materialize(K) = 0`.

**Compare against what exists today**, so the gap is visible from the first page rather than
buried in Teil VI: the entirety of `ssk_bcik::Bcik::cross`'s closure decision, read in full and
verbatim (`crates/ssk-bcik/src/lib.rs:93`; re-anchored 2026-08-11 — S1's edits moved this from `:72`,
where the old citation now lands inside a doc comment):

```rust
if candidate.seam_ok && candidate.boundary_complete {
```

— itself resolved upstream to five string-non-emptiness checks (`crates/ssk-stitch/src/lib.rs:15-29`,
read in full earlier in this session; re-anchored 2026-08-11 from `:14-28`):

```rust
fn seam_ok(facet: &MirrorFacet, locator: &ssk_types::LocatorFacet) -> bool {
    !facet.trace.0 .0.is_empty()
        && locator.health == HealthStatus::Live
        && locator.route != RouteClass::Denied
}
fn boundary_complete(facet: &MirrorFacet) -> bool {
    !facet.boundary.0 .0.is_empty() && !facet.residue.0 .0.is_empty()
}
```

None of `Fix(T)`, `Int(H⁻_Σ)`, the projector algebra `B/B⁻`, `Pass(G)` as a 9-gate conjunction,
or `PathInv` exist anywhere in this predicate. It is two booleans, resolved to non-empty-string
checks. This is the precise, evidenced content behind the earlier (this session's) finding that
`docs/IMRT_IMPLEMENTATION_SPEC.md`'s own row for IMRT axiom A9 grades this "Partial — closure from
boolean flags."

## 8. H-instance, F-instance, and the Import-Gate

> **Definition 10.1 (H-Instanz und F-Instanz).** Die H-Instanz (Härtung) akzeptiert nur getypte,
> gegatete, replayfähige und claim-bereinigte Strukturen. Die F-Instanz (Forschung) darf Hypothesen
> erzeugen, Bilder schärfen und neue Modelle formulieren; ihre Ergebnisse sind nicht automatisch
> Teil des Kerns.
>
> **Definition 10.2 (Import-Gate F → H).** Eine F-Hypothese `x` darf genau dann nach H importiert
> werden, wenn
> `Import_{F→H}(x) = 1 ⟺ Typed(x) ∧ BoundaryDefined(x) ∧ Closed(x) ∧ Pass(G)(x) ∧ τ(x) ∧ Replay(x) ∧ NoOverclaim(x)`.
> Alles andere bleibt F-Material.

**This is the seam the marker-source decision (recorded below) hangs on.** An `Observed` marker —
anything derived from a projection (`GetExtendedTcpTable`, a caller-supplied string) — lives in F
by construction. Only a value carrying genuine kernel-verified evidence can ever satisfy
`Import_{F→H}`, and *"no intrinsic marker source installed"* is not a failure state to hide — it is
the F-instance's correct, honestly-surfaced resting state.

---

# Teil III — Pi-Seam layer

**In scope**, per the recorded decision. PZBA (Pi-Zeta Boundary-Assimilation, the arithmetic
critical-strip coupling layer) and Prime Boundary Atomics are the monograph's own separate research
program (its §18–22) and are **not** instantiated against this codebase — cited in Anhang F, not
modeled here.

## 9. Closed base, open lift

> **Definition 12.1 (Universelle Kreisüberlagerung).** Die geschlossene Kreisphase ist der Quotient
> `S¹ ≅ ℝ/2πℤ` mit universeller Überlagerung `q: ℝ → S¹, q(θ) = e^{iθ}`.
>
> **Satz 12.2 (Geschlossene Basis, offener Lift).** Jede Kreisbahn vom Windungsgrad `m ∈ ℤ` ist im
> Basisraum geschlossen und im Lift um `2πm` verschoben. Für `m ≠ 0` gilt `q(θ+2πm) = q(θ)`, aber
> `θ+2πm ≠ θ`.

## 10. Pi-Seam, half-turn involution, and self-adjointness

> **Definition 13.1 (Pi-Seam).** Der Pi-Seam ist die Half-turn-Seam-Menge `Σ_π = π + 2πℤ ⊂ ℝ`. Ihr
> Bild im Kreis ist der Antipodenpunkt `q(Σ_π) = {−1} ⊂ S¹`. Der Pi-Seam ist ein markierter Schnitt
> der Koordinatisierung, kein Systemzustand: `π ∈ Seam(q)`, `π ∉ X`.
>
> **Definition 13.2 (Half-turn-Involution und Pi-Projektoren).** Auf `L²(S¹)` sei
> `(R_πf)(θ) = f(θ+π)`. Dann `R_π² = I`, **und bei symmetrischer Massstruktur ist `R_π`
> selbstadjungiert**, mit `B_π = ½(I+R_π)`, `B_π⁻ = ½(I−R_π)`.

**This is the precise, monograph-native reading of "selbstadjungiert" — use it, do not substitute
a weaker or invented reading.** `R_π`'s self-adjointness is a stated, D2-provable property of the
half-turn involution on `L²(S¹)` under symmetric measure, not an analogy to categorical
self-adjointness (which would need a dagger/enriched structure neither monograph supplies — that
reading is explicitly rejected below in §13's honesty note).

> **Proposition 13.3 (Projektorzerlegung).** `B_π² = B_π`, `(B_π⁻)² = B_π⁻`, `B_πB_π⁻ = 0`,
> `B_π + B_π⁻ = I`.

**This is the real content behind "boundary complete."** Complementary, idempotent, orthogonal
projectors — an actual algebraic test — is what should eventually replace today's
`!facet.boundary.0.0.is_empty()` (`crates/ssk-stitch/src/lib.rs:26-28`), which tests only that an
opaque string id (`BoundaryRef`, `crates/ssk-types/src/lib.rs:46` via the `id_type!` macro) is
non-empty. `BoundaryRef` carries no internal structure today to which a projector could even apply
— this is named as a required type change in Teil VI/VIII, not assumed away.

## 11. Seam-crossing count and the monodromy ratchet

> **Definition 14.1 (Orientierte Seam-Crossing-Zahl).** Für `a ≤ b` sei
> `c_π(a,b) = #{k ∈ ℤ : a < π+2πk ≤ b}` und `c_π(a,b) = −c_π(b,a)` für `a > b`.
>
> **Definition 14.3 (Automatischer Gangindex).** Ein diskreter Phasenprozess `(θ_n)` trägt den
> Gangindex `g_{n+1} = g_n + c_π(θ_n, θ_{n+1})`, `g_0 ∈ ℤ`. Der Index wird nicht extern bedient,
> sondern durch den Pfad selbst fortgeschrieben (passive Schaltstelle).
>
> **Satz 14.4 (Seam-Crossing als Ratchet-Schritt).** Ist `(θ_n)` monoton steigend und
> `θ_n ∉ Σ_π`, so ist `g_n` monoton nichtfallend; jeder überschrittene Pi-Seam erzeugt genau einen
> positiven Gangschritt.
>
> **Bemerkung 14.10 (Gerichteter Fortschritt).** Der Ratchet macht zyklische Wiederkehr zu
> gerichteter Akkumulation: dieselbe Kreisposition, aber ein fortgeschriebener Gang-, Historien-
> und Filtrationsindex. Dies ist die formale Form des "nicht zurücklaufenden" Prozesses des
> Korpus — ohne jede physikalische Behauptung.

**This is the formal reading of the user's "720°."** Two half-turns, mediated by `R_π`, tracked by
a strictly monotone gang index `g` that never resets — not a spin-physics claim, exactly as
Bemerkung 14.10 states of its own accord.

**Compare against the codebase's own existing (but structurally weaker) 4π-closure**, `ssk_imdf::closure::FourPiClosure`
(`crates/ssk-imdf/src/closure.rs`, read in full for this document). Its own module doc already
cites "IMDF 11; IMRT Axiom A7, Satz 12.4" directly — this file is *already* an IMRT-conformant
implementation, not raw material this document is mapping for the first time:

```rust
pub enum Orientation { Plus, Minus }
impl Orientation {
    pub fn after_turns(turns: usize) -> Self {
        if turns.is_multiple_of(2) { Orientation::Plus } else { Orientation::Minus }
    }
}
```

This is the ℤ/2 grade of an *even/odd pass count* — real, tested (`orientation_is_zz2_graded`,
`closure.rs:231-238`), but it is **not** the monograph's `R_π`/gang-index construction: there is no
seam-crossing counter `c_π`, no continuous phase `θ`, and — the concrete, load-bearing defect,
confirmed by direct read — `evaluate()` inspects only the first two recorded passes:

```rust
let oriented_return = self.passes.len() >= 2
    && self.passes[0].digest == self.passes[1].digest
    && orientation == Orientation::Plus;
```

(`crates/ssk-imdf/src/closure.rs:142-144`). A cascade of depth greater than two is silently
truncated to its first rung — passes at index ≥2 are recorded (`record_pass` pushes them,
`closure.rs:115-117`) but never consulted. **A correction to `docs/IMRT_IMPLEMENTATION_SPEC.md`'s
own top-level roll-up table is warranted here**: that document's row 11 ("FourPiClosedOrResidued")
states *"the second Satz 12.4 conjunct … is never evaluated and no Gegenhorizontmasse residue is
emitted"* — that is no longer accurate. Direct read confirms both conjuncts are evaluated
(`closure.rs:140-149`) and a real Gegenhorizontmasse residue is emitted on a genuine mismatch
(`closure.rs:151-172`, test `drifted_self_class_yields_gegenhorizontmasse_not_closure`,
`closure.rs:288-301`). That document's own explicit caveat (`IMRT_IMPLEMENTATION_SPEC.md:50-53`) —
its top table is an as-audited snapshot and its `§5a Resolution Log` is authoritative for current
status — already anticipates exactly this kind of drift; this document's correction should be read
as confirming that caveat, not contradicting the spec.

**What remains a genuine defect, independent of the above correction:** the Gegenhorizontmasse
residue is emitted as a bare `Digest` (`closure.rs:163-171`), which never enters a
`ResidueRegister` and which no gate ever reads — and, separately, the entire module has **zero
downstream callers**; `ssk-crown`/`ssk-system` (the only two crates depending on `ssk-imdf`) import
only `QLogicGate`/`QLogicInput`. This is the document's **Realized-but-Dead** verdict, formalized in
Teil VI.

## 12. The exponential growth law

> **Proposition 14.9 (Expansionsgesetze und Spiralen).** Eine ganggetriebene Radialvariable
> `r: ℤ≥0 → ℝ≥0` liefert: das exponentielle Gesetz `r_{g+1} = λr_g` (`λ > 1`) ergibt `r_g = r_0λ^g`
> und die logarithmische Spirale `r(θ) = r_0 exp(logλ/2π · θ)`.

**This is flagged, D3/Forschungsprogramm, as the strongest available candidate reading of "reine
exponentielle Spannung"** — the growth-rate parameter `λ` is the "Spannung." The monograph does not
itself decide which side of the growth law (intrinsic gang-driven radius vs. an extrinsic
counterpart) plays "intrinsisch" and which "extrinsisch" in the user's original phrasing; assigning
that is this document's own instantiation choice, not something either monograph proves — it is
carried forward as an open item in Anhang E, not silently resolved here.

## 13. QSNA and the peristaltic cycle — the formal content of "Nullpunktkaskade"

> **Definition 15.1 (QSNA).** Ein Zustand `S ∈ X` ist ein quasi-singulärer nicht-singulärer
> Attraktor, wenn `QSNA(S) = 1 ⟺ SingLike(S) = 1 ∧ Sing(S) = 0 ∧ Pass(G)(S) = 1 ∧ τ(S) = 1 ∧ Replay(S) = 1`.
>
> **Definition 15.3 (Urprojektion und Nullanker).** Die ideale Urprojektion `Π_0` ist kein
> Systemzustand: `Π_0 ∈ A` mit `A ∩ X = ∅`. Ein Boundary-Sediment ist ein Zustand `S_n ∈ X` aus
> einem gate-bestandenen Boundary-Ereignis, `S_n = Sed(e_n)`.
>
> **Definition 16.1 (Peristaltische Boundary-Assimilation).** Peristaltische Boundary-Assimilation
> ist der Zyklus
> `K_n → ExCal(K_n) → G_n → S_n = Sed(e_n) → K_{n+1} = Assim(K_n, S_n) → Σ_{n+1} = Renew(Σ_n, S_n)`.

This cycle *is* the formal content of "Nullpunktkaskade": each level's zero-anchor is the
Urprojektion `Π_0` (never a system state itself — RDA's `N_int` under a different name, structurally
matching `ssk_imdf::NullAnchor`'s non-`Serialize` invariant, Teil VI), and the cascade is the
iterated peristaltic assimilation across levels.

**The chosen levels for this profile, stated as this document's own instantiation, not the
monograph's decision:** **crossing → run → session** — not "app." Per-app attribution is Teil V,
deliberately deferred until the spine (Teil II–IV) is wired; letting the cascade's level count leak
the per-app target into the spine stage would silently reintroduce the sequencing the user
explicitly reversed (below).

---

# Teil IV — Gridlock

**In scope**, per the recorded decision — the aggregate/distributed half of the model.

## 14. Seam-locked families and Lattice Health

> **Definition 23.1 (Gridlock-gekoppelter BCIK).** Für eine Familie `{K_i}_{i∈V}` über einem
> Kopplungsgraphen `(V, E)` ist
> `G-BCIK({K_i}) = 1 ⟺ ∀i: BCIK(K_i) = 1, ∀(i,j) ∈ E: d_N(π_i, π_j) ≤ ε_seam, H_lattice ≥ η`,
> und die globale Quotientenprojektion ist wohldefiniert. Zwei Knoten sind seam-locked, wenn
> `κ_ij = d_N(π_i(S_i), π_j(S_j)) ≤ ε_seam`; die Lattice Health ist
> `H_lattice = r · |{(i,j) ∈ E: κ_ij ≤ ε_seam}| / |E|` mit Kuramoto-Ordnungsparameter `r`.
>
> **Definition 23.2 (Omnipol als Quotient/Colimit).** Seien `S_i` Facettenfelder über `(V, E)`. Der
> Omnipol ist der Quotient `Ω* = (⊔_{i∈V} S_i) / ∼_N`, `x ∼_N y ⟺ π(x) = π(y)` im Nullcenter-Raum;
> kategoriell der Coequalizer der Überlappungsabbildungen. Die Begriffe Ophanim, Monolith und
> Omnipol bezeichnen ausschließlich diese Quotientenstruktur, **keine Entitäten**.
>
> **Proposition 23.3 (Gridlock unter kleiner Drift).** Ist ein Gitter zum Zeitpunkt `n`
> gridlock-erhaltend und gilt für jeden Knoten `d_{S¹}(θ_i^{n+1}, θ_i^n) ≤ η` sowie für jede Kante
> `d_{S¹}(θ_i^n, θ_j^n) + 2η ≤ ε_seam`, so bleibt es zum Zeitpunkt `n+1` gridlock-erhaltend.

## 15. The concrete target for this layer in the spine stage

Nothing in this codebase today asks the aggregate question Gridlock formalizes. `ssk-crown`'s
`CrownSupervisor` and `ssk-daemon`'s state machine evaluate *one* crossing, *one* kill-switch, *one*
session at a time — there is no notion of "is the full current set of live BCIK crossings in this
run collectively seam-locked." The concrete instantiation target, once the spine is wired: the
daemon's aggregate `Protected`/`Degraded` state, generalized from "one session's kill-switch is
individually consistent" to `H_lattice` over every crossing the current run holds open. This is
named here as the target, not scheduled — per the recorded sequencing decision, Gridlock wiring is
part of the spine stage (S1, Teil VII), which precedes any per-app work.

---

# Teil V — Deferred instantiation target: per-app attribution

**Model only. Nothing in this Teil is scheduled before the spine (Teil II–IV) closes** — this is a
deliberate reversal of an earlier planning pass's own recommendation (which argued per-app
attribution was higher-leverage and should be built first); the user chose the opposite ordering,
and it is encoded faithfully here and in Teil VII's staging. This Teil exists so that S1's spine
wiring is built against a signature that already anticipates per-app as its first real consumer,
without pulling per-app work forward.

## 16. The anti-instance already in the codebase

`FlowDescriptor.app_id` (`crates/ssk-netadmin/src/flow.rs:31-33`, read in full for this document):

```rust
pub struct FlowDescriptor {
    /// Identifier of the application or subsystem originating the flow.
    pub app_id: String,
    // ...
}
```

One untyped `String` field simultaneously abused as Marker, Claim, and Observation — exactly the
collapse the monograph's H/F split and RDA's triple separation both forbid. Confirmed production
fabrication sites (grep-verified, matching this session's earlier direct verification):
`ssk-daemon/src/supervisor.rs:546-547` (`"sskd-activate"`, a hardcoded literal),
`ssk-daemon/src/supervisor.rs:720-721` (`"unknown-app"`), `ssk-cli/src/main.rs:5088` (a `--app-id`
CLI flag — user-typed, unauthenticated), `ssk-cli/src/main.rs:5187-5188` (`"demo-app"`).

`MatchCriteria.app_prefix` (`crates/ssk-netadmin/src/policy.rs:32-34`, read in full):

```rust
/// Glob-style app identifier prefix.  `None` matches any app.
pub app_prefix: Option<String>,
```

matched at `policy.rs:51-54` via plain `str::starts_with` — despite the doc comment's "glob-style"
claim, no globbing occurs. `app_prefix: Some(..)` appears in zero production rules — every rule in
this codebase's reference policy engines sets it `None`. App-based matching has never been
exercised outside unit tests.

## 17. The triple separation this codebase already independently enforces

`crates/ssk-winhost/src/pipe.rs:36-46` (read in full for this document), on why
`GetNamedPipeClientProcessId` is deliberately *not* used for peer identity:

> `GetNamedPipeClientProcessId` exists in windows-sys 0.59 and works, but it answers the wrong
> question. It yields a PID, and PIDs are recycled: the sequence PID → `OpenProcess` →
> `OpenProcessToken` → `TokenUser` has a TOCTOU window in which the connecting process can exit and
> its PID be reused by an unrelated one. … It answers "who owns *a* process with this PID *now*",
> not "who is on the far end of this pipe". `ImpersonateNamedPipeClient` asks the kernel for the
> security context captured at connect time, which is the actual question.

This is, verbatim in effect, RDA's Marker ∩ Token = ∅ (a PID is `Token`-shaped: transferable,
recycled, non-intrinsic) and Satz 12.7 (the type error is observer-side) — arrived at independently,
four months before either monograph was read against this codebase, by an engineer solving a
concrete Windows security problem. **Per-app steering must inherit this same refusal as a
first-class model property, not as a local judgement call repeated ad hoc.** TUN→PID reverse
mapping — the design `docs/P4_FULL_COVERAGE_FEASIBILITY.md` already rejected on its own grounds,
and which broke in a mature Go product in production (sing-box issue #2823, cited in that same
document) — is `Phantomize(x,o) = 1` (monograph Def 12.5) by construction. This document's
contribution is naming that rejection as a theorem-shaped consequence of the model, not inventing a
new argument for a design already correctly avoided.

## 18. RootMarker granularity — the recorded decision

Per the user's explicit choice: **signed identity preferred; canonicalized image path as an
explicit, honestly-weaker fallback.** Modeled as a two-grade evidence type, never silently coalesced:

- **Grade 1 (stronger, H-instance-eligible when verified):** a code-signature check over the
  process image at connect time. Answers "always Chrome" independent of install location; forgeable
  only by defeating code signing.
- **Grade 2 (weaker, F-instance only):** the canonicalized executable image path. Forgeable by
  copying the binary to the marked path — must never be promoted to Grade 1's evidentiary weight,
  and any attribution built on Grade 2 alone carries a visible, typed marker saying so.

Neither grade is available from this codebase today without a kernel-mode component (a WFP ALE
callout, per `docs/P4_FULL_COVERAGE_FEASIBILITY.md`'s own Block C costing) — the marker-source
staging decision (below) is precisely what lets the model ship coherently before that component
exists.

## 19. Closure-failure behavior — the recorded decision

Per the user's explicit choice: **configurable per policy rule**, not one hardcoded path. Both
outcomes are legitimate values in the monograph's own decision lattice:

> **Definition 17.1 (Entscheidungsraum).** `D = {Fail, Residue, Fork, Quarantine, Hold, Pass, Commit}`.

Modeled as two typed outcomes of the same closure predicate on attribution failure:

- **`Hold`** — residue emitted, this rule does not fire, the flow proceeds under whichever *next*
  applicable rule matches (or the policy engine's own fail-closed default, unchanged).
- **`FailClosed`** — residue emitted, the flow is refused outright.

This is a **policy-level choice of which lattice value a given rule maps an attribution failure
to** — not a structural fork in the model itself. The existing policy engine's own default
(`PolicyAction::FailClosed` when no rule matches, `crates/ssk-netadmin/src/policy.rs`) already
establishes fail-closed as the *system* default; a rule's own attribution-failure behavior is a
narrower, explicit override on top of that, never a relaxation of it.

## 20. Marker source — the recorded decision, and the honest limit it does not remove

**Staged conformance, not a forced driver commitment.** The model must represent "no intrinsic
marker available" as a first-class Hold/Residue state, never a silent guess. Stated plainly,
against RDA's own discipline (Invariante 34.1: *"Tomographie ist kein Gedankenlesen"* — only what a
declared measurement operator observes is reconstructed) and Satz 15.7 (a proof inherits the bound
of its underlying witness contract): **this model does not eliminate the need for a real kernel
hook for full attribution — it reframes the gap so a driver-less build ships coherently rather than
guessing.** A rule that names an app on a marker-less installation legitimately resolves to `Hold`
or `FailClosed` per §19, provably, rather than reading a stale/racy `GetExtendedTcpTable` snapshot
as fact.

Stated with equal honesty in the other direction: the claim *"we never misattribute"* has content
only once paired with a measured coverage rate of Grade-1/Grade-2/no-marker flows in a real
deployment; without that number it is unfalsifiable, which under the monograph's own A8/A12
discipline (no claim beyond what a declared measurement operator supports) disqualifies it as
stated. And shipping a Proxifier-parity comparison in product copy (`README.md:320`,
`docs/DESKTOP_CLIENT_ARCHITECTURE.md:601-605`) alongside a model that can legitimately refuse
attribution is a real, unresolved tension — a product-copy decision for a later phase, not
something this specification resolves or should paper over.

---

# Teil VI — Profil SSK/IMRT

The conservative-embedding table proper, per RDA's own Anhang D pattern (which already lists
profiles SAA, QOFC/APZΩ, ADAMANT/Tetragrammaton, LOOM/PHC — kaleidoscorp.io is not among them; this
Teil is the missing profile). Verdict vocabulary: **Realized / Partial / Divergent / Absent**
(reused exactly from `docs/IMRT_IMPLEMENTATION_SPEC.md`'s own table), plus this document's own
**Realized-but-Dead**.

| Monograph/RDA element | SSK object | Verdict |
|---|---|---|
| `Ψ` mirror involution (RDA Def 4.1, `Ψ² ≅ id`) | — | **Absent.** Two `Orientation` types exist and neither is an endofunctor. `ssk_types::Orientation{Forward,Reverse}` (`crates/ssk-types/src/lib.rs:194-202`) is hardcoded `Forward` at every production site (`crates/ssk-core/src/lib.rs:87-88`, `MirrorOrbit::derive`), with exactly one consumer workspace-wide (`crates/ssk-stitch/src/lib.rs:46-48`, `focus_ready`). `ssk_imdf::closure::Orientation{Plus,Minus}` (`ssk-imdf/src/closure.rs:24-31`, read in full) is a real ℤ/2 grade *of a pass count*, with no action on objects. |
| `N_int` / `Z_∂` dual null structure, RDA **Axiom A5** (`N_int ≇ Z_∂`) | `ssk_imdf::self_anchor::NullAnchor` (`crates/ssk-imdf/src/self_anchor.rs:97-171`, read in full) | **Realized-but-Dead, and a RDA A5 problem.** Genuinely, correctly non-`Serialize` (`Z_∂`'s non-inhabitability, structurally enforced — confirmed by contrast against the same file's `SelfAnchor`/`DomeLocator`/`BcikCrossing`, which do derive it) *and* orders a `SelfAnchor` via `NullAnchor::order` (`self_anchor.rs:154-170`, tested at `:319-342`) — `N_int`'s coupling role. One type discharging both roles the axiom requires kept separate. **Splitting this type is a required breaking change under the axiom, not optional cleanup** (see Teil I §2). |
| `N_int`/`Z_∂` (2nd, unrelated claimants) | `ssk_bcik::NullRef`, `ssk_bcik::BoundaryOperator` (`crates/ssk-bcik/src/lib.rs:9-24`, read in full) | **Name-only.** Both empty, `Default`-derived unit structs, `_`-prefixed on the `Bcik` struct, never read anywhere in `cross()`'s body. |
| `W_0` absolute-witness operator (`W_0(e) = (neutralize charge, preserve trace, emit receipt, route residue)`) | `Bcik::cross`'s residue branch (`crates/ssk-bcik/src/lib.rs:96-108`, read in full) | **Partial.** Neutralizes charge (no stitch emitted) ✓; preserves trace (`facet.trace.clone()` on the residue) ✓; routes residue (`self.residue.emit(residue.clone())`) ✓; **emits no receipt** ✗; and — the concrete, verified defect — **emits byte-identical residues whether `seam_ok` or `boundary_complete` was the failing conjunct** (`"BCIK crossing not boundary-closed"` is the sole message for both cases) — a Vertrag 27.2 violation (a non-Pass outcome must carry a distinguishing `ResidueCode`). |
| 4π-Closure (RDA Def 7.5 / monograph's Pi-Seam machinery) | `ssk_imdf::closure::FourPiClosure` (`crates/ssk-imdf/src/closure.rs:104-215`, read in full) | **Realized-but-Dead.** Both Satz-12.4 conjuncts genuinely implemented (`:140-149`), a real Gegenhorizontmasse residue emitted on mismatch (`:151-172`), all tested (`:217-302`). **This corrects `docs/IMRT_IMPLEMENTATION_SPEC.md`'s own stale top-table row** — see Teil III §11. Real, live defects that remain regardless: `evaluate()` inspects only `passes[0]`/`passes[1]` (a cascade of depth > 2 is silently truncated); the Gegenhorizontmasse residue is a bare `Digest` that reaches no `ResidueRegister` and no gate; and the module has zero downstream callers (`ssk-crown`/`ssk-system` import only `QLogicGate`/`QLogicInput`). |
| `L ⊣ J` reflective adjunction (RDA Axiom 8.1) | — | **Absent.** No reflector, no closure monad, no idempotence anywhere in this codebase. |
| `(Ctx, J_cov)` reflection situs (RDA Def 9.1) | — | **Absent.** `CaptureScope` (`ssk-capture`) is a label plus a source list, not a site with a covering topology. |
| Holographic sheafification `a` (RDA Satz 10.4) | — | **Absent.** |
| Residue taxonomy (monograph Tab 11.1 / RDA's Obstruktions- und Residuenstruktur) | `ssk_types::ResidueKind` (`crates/ssk-types/src/lib.rs:682`, per this session's earlier direct verification) | **Partial.** A closed, append-only taxonomy exists and is genuinely enforced; missing exactly the four this profile needs: Dual-, Kalibrier-, Provenienz-, Zeitresiduum. |
| `ρ` RootMarker (RDA Def 12.1) | — | **Absent.** `FlowDescriptor.app_id: String` (`crates/ssk-netadmin/src/flow.rs:33`) is the anti-instance — see Teil V §16. |
| Root-Claim (RDA Def 12.3) | `RouteTraceRequest.app_id`, `--app-id` CLI flag | **Divergent.** It *is* a claim in RDA's sense, but is untyped as one, carries no signature and no provenance witness, and is trusted at face value. |
| Observerprojektion `Π_o` (RDA Def 12.4) | `ssk_winhost::connections::FlowRow.pid` | **Partial — computed and thrown away.** The PID is genuinely parsed from the real IP-Helper table (per this session's earlier direct verification of `connections.rs`), but the conversion into `ssk_capture::TrafficWindow` never reads it, and `TrafficWindow` (`crates/ssk-capture/src/lib.rs:68-79`) has no field to receive it. |
| PhantomToken (RDA Def 12.5) | — | **Absent — the dangerous gap.** Nothing in the tree can *name* a misattribution as such, so nothing can route one to a residue instead of silently trusting it. |
| Identitätsclosure (RDA Def 13.7) | — | **Absent.** No equalizer construction exists anywhere relating an intrinsic and an extrinsic section of anything. |
| Doppelchronologie `τ = (τ_i, τ_e)` (RDA Def 14.3) | — | **Absent.** `EpochId`, `intake_epoch`, `Ttl` are all single-clock. |
| `W_F`/`W_0`/`W_S` witness roles (RDA Ch. 15) | `GateWitness`, `SeamWitness`, `CapabilityWitness` | **Divergent.** All three existing witness types are `W_F`-shaped (declarative, fallible). No `W_S` (ShadowWitness) exists anywhere. |
| ConsensusForgery (RDA Def 16.1) | — | **Absent.** |
| Entscheidungslattice (RDA Def 17.1 / monograph Def 17.1, both `D`) | `GateVerdict` (per this session's earlier direct verification, `ssk-types/src/lib.rs:1042-1048`) | **Partial.** 5 states {Pass, Hold, Refine, Reject, Quarantine} vs. the monograph/RDA's 7 {Fail, Residue, Fork, Quarantine, Hold, Pass, Commit}. Missing `Fork` and `Commit`-distinct-from-`Pass`; `Refine` has no RDA/monograph analogue. |
| Gate-Kaskade (RDA Tab 17.1, 11 gates / monograph's 9-gate family, Def 7.1) | `GateId` (12 members, `crates/ssk-types/src/lib.rs:637-650`, confirmed by direct grep) | **Divergent-but-comparable.** No SSK gate covers `ProjectionGate`, `RootMarkerGate`, or `DualGate` — the three gates attribution most needs. `GateId::Bcik` exists (`:641`) and `ssk_gates::BcikGate` implements it (`ssk-gates/src/lib.rs:150-178`, confirmed by direct grep — its own doc comment already reads "BcikGate: seam, boundary, residual projector, no silent crossing"), but drives the same two-boolean predicate named in Teil II §7. |
| `Γ^(2)` second-order gate (RDA Def 18.2 / monograph's `G^(2)`) | — | **Absent.** Every existing gate is first-order over a single `StitchCandidate`; nothing checks compatibility across a coupling family. |
| Framework-ID / content addressing (RDA Def 25.2) | `content_id!` macro, `digest_of` | **Realized.** The strongest existing conformance in this profile — used correctly and pervasively (e.g. `SelfAnchorId`, `LocatorAddressId` in `self_anchor.rs:18-19`). **One concrete defect within it**: `Bcik::cross`'s `seam_bytes.try_into().unwrap_or([0u8; 32])` (`crates/ssk-bcik/src/lib.rs:99`, re-anchored 2026-08-11 from `:76`) silently produces an all-zero seam witness on any hash-length mismatch, and its `StitchId::new(format!("stitch:{facet}:{locator}"))` (`lib.rs:119-123`, re-anchored from `:79`) omits `fiber`, so a `Control` and a `Data` crossing of the same `(facet, locator)` collide on id. Both are still present in the current tree — S1 explicitly left them in S2's scope, and the code says so at `lib.rs:97-98`. |
| Round-Trip (monograph Vertrag 25.4 / RDA equivalent) | `ssk_imdf::reanalyze`, `DeterministicReplayEngine` | **Realized** / **Realized-but-Dead** respectively (per this session's earlier direct verification of the reanalysis path and the replay engine's own reachability). |
| `epsilon_stitch` calibration tolerance (BCIK **A12**-equivalent / RDA's Zwei-Skalen-Kalibrierpflicht) | — | **Absent, and disclosed as such by the code itself.** `ssk_types::BoundaryRecord`'s own doc comment (`crates/ssk-types/src/lib.rs:568-572`) already states the residual projector's tolerance is unmodeled. Under this profile's calibration discipline this is a **live Kalibrierresiduum**, not a deferred TODO — this document deliberately assigns it no number, since doing so from closure alone would itself violate the calibration axiom; it requires measurement against real captured traffic, which does not exist yet. |

---

# Teil VII — Wiring discipline

This repository has now hit *"built, tested, never called"* three separate times within this same
working session: `ssk-stitch`'s evidence flags before an earlier gate-integrity pass wired them;
the P1 privileged-store lockdown that existed with zero production callers before a follow-up pass
wired it; and now the entirety of the `ssk-imdf` theory surface documented in Teil VI. This Teil
states the mechanism that prevents a fourth instance, as a named Prinzip rather than a process note
easily skipped.

## 21. Wiring by Construction

> **Prinzip (Wiring by Construction).** A theory object may enter the tree only as a required
> constructor argument of an already-live runtime type — never as a sibling module with its own
> isolated tests.

The concrete instance for the S1 stage below: `CrossOutcome::Closed` becomes constructible only by
consuming a real `ClosureReport` value (not a `bool`), so a crossing cannot close without the
Pi-Seam machinery having actually run. This mirrors a pattern this codebase already uses
successfully elsewhere: `ssk_imdf::self_anchor::NullAnchor` deliberately does not derive
`Serialize` (`self_anchor.rs:110`), so the compiler — not a test, not a convention — rejects placing
it in any serialized atlas, ledger, or wire payload. That is the shape to generalize: prefer a
compiler rejection over a green test suite wherever the language allows it.

## 22. Reachability obligations, not test obligations

Every proof-obligation acceptance criterion in Teil VIII reads *"reachable from `sskd`'s real entry
point,"* discharged by an integration test living in a `tests/` directory — never a unit test
living beside the definition it is meant to prove wired. This is the exact coverage shape every one
of Teil VI's "Realized-but-Dead" rows already has: real unit tests, zero reachability.

## 23. The monograph's own justification for this discipline

The Import-Gate (Teil II §8, Def 10.2) already *is* this mechanism, stated by the monograph itself:
an F-instance hypothesis being built and tested in F is explicitly **not** sufficient for
H-instance membership — `NoOverclaim(x)` is one of seven required conjuncts, and none of the
conjuncts is satisfied merely by a hypothesis compiling and its own tests passing. This document's
Wiring-by-Construction Prinzip is the software-engineering-level enforcement of that same gate; it
is cited here as the monograph's own justification, not introduced as an unrelated add-on.

## 24. The staged path

| Stage | Content | Exit gate |
|---|---|---|
| **S0 — Modellierung** | This document. | Reaches internal consistency; Anhang E's open items are either resolved or explicitly logged as Forschungsfragen; the naming collision (Teil I §3) is resolved by grading, not renaming. |
| **S1 — Wire the extant. Zero new concepts.** | `FourPiClosure` becomes a required input to `Bcik::cross`'s real closure decision (Wiring by Construction, §21). `NullAnchor` splits into a genuine `N_int`/`Z_∂` pair (Teil I §2, Teil VI). Gegenhorizontmasse enters a real `ResidueRegister`. The two `Orientation` types reconcile to one. `FourPiClosure::evaluate` handles cascade depth > 2. Gridlock's `H_lattice` is introduced against the daemon's aggregate protection state (Teil IV §15). | Every Teil VI "Realized-but-Dead" row is either reachable from `sskd` with a passing reachability test, or explicitly retired with a recorded reason. **No new theory may be defined until this closes.** |
| **S2 — Repair the crossing's own defects** | `lib.rs:99`'s silent all-zero seam witness; `lib.rs:119-123`'s fiber-omitted id collision; the byte-identical dual-cause residue (Teil VI). Redundant `facet`/`loc` parameters on `Bcik::cross` (already redundant with `candidate.facet`/`candidate.locator`). *(Line numbers re-anchored 2026-08-11 from `:76`/`:79`; see §26.)* **Survives verbatim per ADR 0008**, as decision-core work off the product critical path. | The domain-specific negative tests in Teil VIII pass. |
| **S3a — Die Dyade (types)** | `N_int`/`Z_∂` as genuinely distinct types (the S1 split, hardened); `Ψ` as a real involution; the biconditional identity object as an actual equalizer. **Survives verbatim per ADR 0008**, as decision-core work off the product critical path. | RDA Axiom A5 (Nulltrennung) and the monograph's own A4/A5 (Closure-Pflicht, fail-closed Gate) hold as type-level facts, not conventions. |
| **S3b — `epsilon_stitch` calibration** | `epsilon_stitch` gets a declared, *measured* Feasible Window. **Resequenced after ingress by ADR 0008**, because it needs real captured traffic that does not yet exist (Anhang E item 3, Teil VI's `epsilon_stitch` row). *(Split out of the former single `S3` row on 2026-08-11, per ADR 0008's own S3a/S3b wording; the content is unchanged, only its sequence position.)* | A Feasible Window derived from real captured traffic, not chosen from closure. |
| **S4 — Die Dreifachtrennung im Flow-Modell** | `FlowDescriptor.app_id: String` → a typed `AppAttribution` sum (Grade 1 / Grade 2 / `Observed`-only, per Teil V §18). `MatchCriteria.app_prefix` retyped accordingly. Audit entries carry the attribution *with its grade*. **Moved into the product workspace by ADR 0008**, to land jointly with ingress and to be expressed as `PolicyAction` values rather than `RunOutcome` variants. | The per-app negative test (an extrinsic section that agrees with a caller-supplied string closes without provenance descent) is rejected, provably. **This stage does not depend on S2 or S3a** — it instantiates only Teil II §8's Import-Gate discipline directly, which is already closed at S0. |
| **S5 — Markerquelle** | The marker-source trait, with exactly one honest implementation (`Observed`) until a kernel component exists; `Marked` stays declared-but-uninhabited. **Moved into the product workspace by ADR 0008**, to land jointly with ingress and to be expressed as `PolicyAction` values rather than `RunOutcome` variants. | A rule naming an app on a marker-less build resolves to `Hold`/`FailClosed` per the configured policy (Teil V §19), provably — never a silent guess. |
| **S6 — Kernel-verified marker (Block C)** | Only if separately committed, per `docs/P4_FULL_COVERAGE_FEASIBILITY.md`'s own Block C costing (3–6 months, EV certificate, Microsoft attestation, kernel-mode code in a `forbid(unsafe_code)` repository). **Unchanged by ADR 0008.** | `Marked` becomes inhabited; the Proxifier-parity comparison in product copy becomes truthful rather than aspirational. |
| ~~*(unnumbered)* — connect `sskd`'s supervisor to this decision pipeline~~ | ~~Logged at §24a as an open architectural question with no stage number.~~ **RETIRED by ADR 0008** (2026-08-11). It is not deferred and not renumbered; it is withdrawn, because the thing it proposed to build is not the right thing to build. Reason at §24a. | — |

**S4 is deliberately reachable independently of S2/S3a's completion** — it instantiates only Teil
II §8, already fully specified. This is noted so that, if the spine-first sequencing decision is
ever revisited, the document already states which stage would actually move, rather than requiring
a fresh analysis.

> **Resequenced 2026-08-11 by
> [`docs/adr/0008-flow-path-owns-the-per-connection-decision.md`](adr/0008-flow-path-owns-the-per-connection-decision.md).**
> Corrected in place, per this document's own discipline (§21-23); no row was deleted and no exit
> gate was weakened. The disposition, taken verbatim from the ADR's own wording rather than
> re-derived here:
> - **S4 and S5 move into the product workspace** and land jointly with ingress, expressed as
>   `PolicyAction` values rather than `RunOutcome` variants. Their *content* is unchanged; what
>   changes is which workspace owns them and what type carries the verdict.
> - **S2 and S3a survive verbatim** as decision-core work off the product critical path.
> - **S3b (`epsilon_stitch` calibration) is resequenced after ingress**, since it needs real captured
>   traffic that does not yet exist. This is the same reason Anhang E item 3 already gives; the ADR
>   assigns it a sequence position rather than leaving it unplaced.
> - **S6 is unchanged.**
> - **The unnumbered stage logged at §24a is retired**, with the reason recorded there.
>
> One consequence worth stating explicitly, because it changes the shape of S4/S5 rather than only
> their order: expressing them as `PolicyAction` means the Import-Gate discipline they instantiate is
> discharged on the flow path (`ssk-netadmin`), not inside `run_to_outcome`. §25's **VC10** is
> re-targeted accordingly — see the annotation there.

## 24a. S1 status (verified 2026-08-09)

Mechanically complete for five of six items, each verified by mutation testing rather than read-and-
trust. Corrected in place per this document's own discipline (§21-23) rather than silently marked
done — the first implementation attempt broke the workspace build entirely (a missed production call
site, `ssk-gates`'s `BcikGate::evaluate`) and a second pass repaired it; both passes' findings are
folded into the status below.

- **Item 1 (`FourPiClosure` wired into `Bcik::cross`) — Closed.** `CrossOutcome::Closed` is
  unreachable without a genuine second, agreeing orientation pass (Satz 12.4). The two real passes
  come from control flow that already existed, not fabricated plumbing: `BcikGate::evaluate` (the
  gate-vector pre-check) unconditionally advances the accumulator with a real first pass for every
  candidate before any other gate runs (`GateVector::evaluate` has no early exit); `run_to_outcome`'s
  own materialization crossing supplies the second, genuine pass over the identical seam identity,
  sharing that same `FourPiClosure` instance within one `execute_pipeline` call. Mutation-verified at
  two boundaries: inside `ssk-bcik`'s own crate (`crates/ssk-bcik/tests/reachability.rs`) and,
  separately, from `ssk-runtime::run_to_outcome`'s public API
  (`crates/ssk-runtime/tests/bcik_closure_reachability.rs`) — de-sharing the accumulator between the
  two real crossings correctly turns the latter test red. See the finding below on what "reachable"
  does and does not mean here.
- **Item 2 (`NullAnchor` splits into `N_int`/`Z_∂`) — Closed.** `NullAnchor` (pure `Z_∂` raw material,
  `commitment()` only) and a new `NullFixpoint` (the coupling-active fixpoint, constructible only via
  `NullAnchor::fixpoint()`, with no path back to the raw material) are structurally un-conflatable —
  verified by a test that attempts the collapse and cannot construct one.
- **Item 3 (Gegenhorizontmasse into a real `ResidueRegister`) — Closed.** `FourPiClosure::evaluate`'s
  self-class-drift branch emits a real `ssk_types::BoundaryResidue`, visible in a real
  `ResidueRegister::entries()` enumeration. Recorded honestly: it uses the existing
  `ResidueKind::Identity` rather than a new `ResidueKind::Dual` variant (the implementing agent's own
  design called for the latter but it fell outside that pass's declared file scope) — `Identity` is
  the closest correct existing fit, not a stub, but a future pass should revisit whether `Dual`
  belongs in the taxonomy.
- **Item 4 (`Orientation` reconciliation) — Closed.** `ssk_types::Orientation` is renamed to
  `FacetOrientation`; the transitional alias is removed; every call site is migrated.
  `ssk_imdf::closure::Orientation` (the ℤ/2 spinor grade) remains deliberately distinct — the two were
  disambiguated, never merged, per the rejection of an unearned Synthese (Prinzip 19.3).
- **Item 5 (`FourPiClosure::evaluate` handles cascade depth > 2) — Closed.** Sliding-window evaluation
  (`passes[n-2]`/`passes[n-1]`) replaces the hardcoded `passes[0]`/`passes[1]` indices; independently
  re-derived by hand against a depth-4 cascade and confirmed correct.
- **Item 6 (Gridlock's `H_lattice`) — explicitly retired, not built.** No per-run collection of live
  BCIK crossings exists anywhere in this codebase (`ssk_runtime::run_to_outcome` processes exactly one
  `ConnectionIntent` into one `RunOutcome` per call; nothing accumulates crossings into an enumerable
  family). `ssk-daemon`'s own state (`Supervisor::Inner`) is a single active session, not a family —
  even the daemon's own internal multiplicity does not supply Gridlock's required node set. Building
  either a fabricated single-node instance or an invented multi-field reading would have manufactured
  exactly the kind of structure this document's own ethos forbids. Prerequisites for a later stage: (i)
  this row's own item 1 wiring (now done); (ii) a genuine per-run accumulation of crossings, not yet
  built anywhere. Natural home once real: a new `ssk_imdf::gridlock` module, not `ssk-daemon` itself.

**A new finding, larger than S1's own scope, surfaced during verification and recorded here because
the exit gate's own wording depends on it.** The exit gate above reads *"reachable from `sskd`'s real
entry point... or explicitly retired."* Direct verification (a grep of `ssk-daemon`'s complete source
tree for `run_to_outcome`, `ssk_runtime`, `GateVector`, and `Bcik::` — zero matches) confirms that
**`sskd` does not call into `ssk-runtime`/`ssk-gates`/`ssk-bcik` at all, today, in any form.** It
depends on `ssk-gates` only transitively and at compile time, through `ssk-config`'s unrelated use of
`ssk_gates::pch::Axis`, never invoked at runtime. The only real production caller of `run_to_outcome`
anywhere in the workspace is `ssk-cli`'s `connect_command` (`main.rs:4030`), and even that call passes
a hardcoded `sample_intent(valid_fixture)` rather than a caller-supplied `ConnectionIntent`.

This means the entire decision pipeline this Teil wires — including everything S1 just closed — is
not reachable from the actual running daemon service; it is reachable only from a CLI command
exercising a fixture, not live per-connection traffic. This is not a defect S1 introduced, and S1 was
never scoped to fix it (S1's brief was to wire the machinery *inside* the pipeline, not to wire the
pipeline *into* the daemon). But it means the exit-gate wording above is not literally satisfiable
until a new, currently unscoped stage connects `sskd`'s supervisor to this decision pipeline for real
per-connection traffic. Until that lands, every "reachable from `sskd`" claim in this document
(including in Teil VI's table and Teil VII §22) should be read as *"reachable from `ssk-runtime`'s own
public API, and from `ssk-cli`'s `connect_command` against a fixture"* — a materially weaker claim.
This gap is logged here rather than silently accepted, per this document's own standing discipline;
it is not yet assigned a stage number, since whether it precedes or follows S2–S6 is an open
architectural question, not a mechanical next step.

> **CLOSED 2026-08-11 by
> [`docs/adr/0008-flow-path-owns-the-per-connection-decision.md`](adr/0008-flow-path-owns-the-per-connection-decision.md).**
> The paragraph above is preserved as the record of how the question was found; it is superseded on
> its final sentence only. The question is no longer open, and the stage it anticipated is **retired,
> not deferred and not renumbered** — because the answer is that the connection it proposed should
> not be built.
>
> **The finding itself is confirmed, not overturned.** ADR 0008 independently re-verifies that `sskd`
> does not call `ssk_runtime::run_to_outcome` and will not; `ssk-daemon` does not depend on
> `ssk-runtime` at all (`crates/ssk-daemon/Cargo.toml:11-47`), and its dependency on `ssk-gates`
> exists solely so `ssk-config`'s `HypercubeConfig.axes` can reuse `ssk_gates::pch::Axis` — an edge
> the ADR severs by relocating that enum into `ssk-types`.
>
> **Why the stage is retired rather than scheduled.** The reason is arity, not preference.
> `ssk_types::ConnectionIntent` (`crates/ssk-types/src/lib.rs:622-628`, read and confirmed: fields
> are `run`, `core`, `target_locator`, `capability`, `ttl_epoch`) has **no field that can hold a
> destination host or port**. `ssk_netadmin::FlowDescriptor`
> (`crates/ssk-netadmin/src/flow.rs:31-42`) has `destination_host` and `destination_port`, and does.
> A decision type that cannot name where a packet is going cannot be the per-flow decision type.
> Wiring the decision core into per-connection traffic would instead require fabricating a
> `CoreNode`, a `MirrorFacet` and a `CapabilityWitness` per TCP connection — exactly the synthetic
> evidence ADR 0007 and this document's own ethos exist to prevent.
>
> **What owns the per-connection decision instead**, verified in the working tree: `sskd` builds the
> `FlowDescriptor` itself (`crates/ssk-daemon/src/supervisor.rs:543-553`), runs
> `PolicyEngine::evaluate` → `RouteOrchestrator::plan` (`:554-558`), and dispatches through
> `DataPlane::connect_route` (`:582`) over the real `NetcoreDataPlane`/`RouteExecutor` constructed at
> `crates/ssk-daemon/src/main.rs:272-273`.
>
> **The weakened reading stands, and is now permanent rather than provisional.** Every "reachable
> from `sskd`" claim in this document — including in Teil VI's table and Teil VII §22 — must still be
> read as *"reachable from `ssk-runtime`'s own public API, and from `ssk-cli`'s `connect_command`
> against a fixture"*. That is no longer a temporary state awaiting a wiring stage; it is the decided
> architecture. The S1 exit gate's wording ("reachable from `sskd`'s real entry point... or explicitly
> retired") is satisfied by the second disjunct: the reachability target is retired, with the reason
> recorded here, which is precisely the escape the gate was written to allow.
>
> **What ADR 0008 deliberately does not decide,** and this document must not imply otherwise:
> whether the decision core is extracted into a sibling workspace, and whether the identity-crossing
> spine returns to the product later. The latter is deferred until after ingress, pending three
> measurements that cannot be taken today (per-decision latency at concurrency, tensor growth under
> load, and a real attribution coverage rate). The staged path in §24 is resequenced accordingly —
> see the annotation under that table.

---

# Teil VIII — Proof Obligations, Negativtests, Konformität

## 25. Verification Conditions

Reused verbatim from the monograph (§46), each mapped to a concrete reachability target in this
codebase rather than a bare restatement:

| VC | Monograph statement | SSK reachability target |
|---|---|---|
| VC1 | `Can ∘ Can = Can` | A canonicalization function for `StitchCandidate`/`MirrorFacet` exists and is idempotent — does not exist today; no canonicalization runs anywhere in the crossing path. |
| VC2 | `σ = σ ∘ Can`, complete on the carrier | The seam witness digest must be computed over the canonical form; today it is computed over raw facet/locator ids with no canonicalization step. |
| VC3 | `G(committed ⟹ Closed)` | `CrossOutcome::Closed` must be unreachable without the full `Pass(G)` conjunction — today reachable via two booleans (Teil II §7). |
| VC4 | `G(residue≠0 ⟹ ¬committed)` | Already structurally true in `Bcik::cross`'s current shape (the two branches are mutually exclusive) — the gap is that the residue conjuncts being tested are too weak, not that this VC is violated. |
| VC5 | Erhaltung: every transition preserves BCIK | An integration test asserting a crossing that closes stays closed through the full `run_to_outcome` path in `ssk-runtime`, not merely at the point of `Bcik::cross` — does not exist today. |
| VC6 | Fortschritt: no stall except Closure/Hold | Not modeled at all today; there is no small-step machine in this codebase to check this against. |
| VC7 | Determinism modulo `Can` (Replay) | `ssk_replay::DeterministicReplayEngine` exists and is real (Teil VI) but is not wired to any BCIK crossing. |
| VC8 | Append-only ledger; Monolithen unveränderlich | `ResidueRegister` is genuinely append-only (per this session's earlier verification) — Realized for the residue half; no equivalent exists for a "committed kernel" ledger. |
| VC9 | Datenverfeinerung: `r` injective on canonical classes | Not applicable until VC1/VC2 exist. |
| VC10 | Import-Gate als Admission-Controller, fail-closed | ~~Directly instantiable today as the per-app `AppAttribution` gate (Teil V §18–20, S4) — the one VC reachable independently of the rest.~~ **Re-targeted 2026-08-11 by ADR 0008** onto the dispatch seam: `DataPlane::connect_route` (`crates/ssk-netcore/src/data_plane.rs:33-37`) comes to require an `AdmissionToken` with no public constructor and no `Serialize`, minted only where `RouteCandidate.requires_attestation` has been discharged. Still the one VC reachable independently of the rest; the change is *where* it is discharged, not whether. |

> **VC10 re-targeting — the precise guarantee, and its bound.** Recorded here because an admission
> control whose strength is overstated is worse than none. What the token buys is exactly this: **no
> crate outside the token's defining crate can dispatch without one.** It is not a proof that the
> attestation was correct, only that dispatch cannot occur without the discharge site having run.
>
> The defect it closes is real but currently **latent, not live**: `RouteCandidate.requires_attestation`
> is produced by the `PolicyAction::RequireAttestation` arm
> (`crates/ssk-netadmin/src/route.rs:175-177`, which returns `(inner_route, true)`) and is then
> discarded before dispatch — `crates/ssk-daemon/src/supervisor.rs:554-558` maps the candidate down
> to its `route` alone, and `RouteExecutor::connect` takes only `&RouteKind`
> (`crates/ssk-netcore/src/executor.rs:114-118`). It is latent because the three hardcoded rules the
> daemon ships (`crates/ssk-daemon/src/supervisor.rs:177-219` — actions `Allow`, `Redirect`,
> `Allow`) never construct `RequireAttestation`; it becomes live the moment an operator can write
> such a rule, which is precisely what the routing configuration schema will enable. That is the
> whole argument for closing it before the schema lands rather than after.

## 26. Negative tests

The monograph's own N-01..N-15 (§26) apply generally; three domain-specific ones, each already
concretely demonstrated against real code in this session and restated here as formal obligations
rather than one-off findings:

- **N-BCIK-16**: a hash-length mismatch in seam-witness computation must be rejected, never
  silently coerced to an all-zero witness (`crates/ssk-bcik/src/lib.rs:99`).
- **N-BCIK-17**: two crossings differing only in `FiberType` (e.g. `Control` vs. `Data`) over the
  same `(facet, locator)` must never receive the same `StitchId`
  (`crates/ssk-bcik/src/lib.rs:119-123`).
- **N-BCIK-18**: a residue caused by `¬seam_ok` and a residue caused by `¬boundary_complete` must
  carry distinguishable `ResidueCode`s, never the same message (`crates/ssk-bcik/src/lib.rs`, the
  `else` branch of `Bcik::cross` — see the re-anchoring note below).

> **Citations re-anchored 2026-08-11.** S1's edits to `Bcik::cross` moved every line in this file.
> N-BCIK-16 was cited at `lib.rs:76` and N-BCIK-17 at `lib.rs:79`; **both of those line numbers now
> land inside a doc comment**, which is exactly the silent-drift failure this document's own
> discipline exists to catch. The current anchors, read and confirmed in the working tree:
> `let seam_array: [u8; 32] = seam_bytes.try_into().unwrap_or([0u8; 32]);` at `lib.rs:99`, and
> `StitchId::new(format!("stitch:{}:{}", facet.id.0.to_hex(), loc.id.0 .0))` at `lib.rs:119-123`
> (the `fiber` binding is in scope at that point and is not used in the id). The N-BCIK-18 anchor
> `:96-108` is likewise stale — `:97-98` is now the S2 marker comment, not the residue branch — and
> is left symbolic rather than replaced with a number that will drift again before S2 lands.
> All three defects are still present; none was fixed by S1, which scoped them to S2 (§24).
> Every other citation of `:76`/`:79` in this document (Teil VI §Framework-ID, §24's S2 row, and the
> Teil I comparison at `lib.rs:93`) was re-anchored in the same pass.

## 27. Konformität

The primary grading device for this codebase is the monograph's own H/F-instance distinction
(Teil II §8), **not** an invented numbered ladder — the monograph defines none, and inventing
"BCIK-0..6" here would duplicate RDA's own RDA-0..RDA-6 ladder, which already exists for grading how
this whole profile embeds into RDA (Teil I §1). Stated plainly: today's `ssk-bcik` and `ssk-imdf`
closure code sits in **neither instance cleanly** — it is F-shaped work (untested against the real
invariants, no Import-Gate ever evaluated) wearing H-shaped naming (`Bcik`, `BcikGate`,
`GateId::Bcik` all imply hardened, kernel-grade status their own behavior does not support). Closing
S1–S3 (Teil VII) is what would move it genuinely into H.

---

# Anhänge

## A. Axiom-/Invariantenregister

RDA A1–A12 / I1–I12 remain the normative parent set (Teil I §1). The monograph's own A1–A8 (Teil II
§5) are the operative axioms for everything built under this spec. No axiom from either system is
restated with a new number in this document; where a local clarification was needed (RDA A5 vs.
BCIK A5, Teil II §5), it is disambiguated by system name inline, not renumbered.

## B. Symbolverzeichnis

Both monographs' notation is used as-is. One collision checked and resolved: both use `B`/`B⁻` for
boundary-adjacent projectors — confirmed to be the *same* construction (`B = ½(I+R)`,
`B⁻ = ½(I−R)` in both the monograph's Def 5.1/13.2 and structurally identical role in RDA's
`Nint`/boundary discussion), so the notation is merged without qualification.

## C. Profil SSK/IMRT

The full table is Teil VI, above.

## D. Crosswalk RDA ↔ IMRT ↔ SSKΩ ↔ monograph

Per-row conservativity/retraction verdicts are given inline in Teil I §2 for the two worked
examples (IMRT A7, IMRT A1). A full row-by-row crosswalk of all of IMRT's A1–A10 against RDA and
the monograph is deferred — it duplicates significant material already present in
`docs/IMRT_IMPLEMENTATION_SPEC.md`'s own 63-row table and its `§5a Resolution Log`, and repeating it
here risks exactly the kind of drift this document corrected once already (Teil III §11). Cite that
document directly rather than forking its table.

## E. Offene Fragen

1. Which side of Proposition 14.9's exponential growth law (Teil III §12) is "intrinsic" and which
   "extrinsic," in the user's original framing — this document flags the candidate reading but does
   not resolve the assignment.
2. Whether the Kuramoto order parameter `r` in Gridlock's `H_lattice` (Teil IV §14) should be
   computed over crossing phase, run phase, or session phase, once S1 picks a concrete cascade
   instantiation beyond the three named levels (Teil III §13).
3. The `epsilon_stitch` calibration window (Teil VI) remains genuinely unset — it requires
   measurement against real captured traffic that does not exist yet, and no amount of further
   modeling resolves this; it is an empirical task for whenever real traffic data exists, not a
   number this document can choose.

## F. Quellen

- *"Rahmenwerk dualer Attraktorgeometrien"*, Band 0, Version 1.0, 2026 — cited as **RDA** throughout.
  Not committed to this repository.
- *"Boundary-Closed Invariant Kernels"*, Monographie v1.0, 2026 — cited as **the monograph**
  throughout. Not committed to this repository.
- `docs/IMRT_IMPLEMENTATION_SPEC.md` — this repository's existing IMRT conformance audit; cited
  directly rather than duplicated (Anhang D).
- `docs/OMEGA_CORE_CONFORMANCE_SPEC.md` — this repository's SSKΩ-0..9 ladder (Teil I §2).
- `docs/P4_FULL_COVERAGE_FEASIBILITY.md` — the per-app/WFP-driver costing referenced in Teil V §20.
- `docs/adr/0007-rda-bcik-metacalculus.md` — the accompanying architecture decision record.
