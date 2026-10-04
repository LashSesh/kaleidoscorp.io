# ADR 0007: RDA as Metacalculus, BCIK as Its Band 1, IMRT Embeds Conservatively

## Decision

Adopt "Rahmenwerk dualer Attraktorgeometrien" (RDA) as the normative parent metacalculus for this
project's theory-adjacent crates, and the "Boundary-Closed Invariant Kernels" monograph (BCIK) as a
conservative Sektion (Band 1) of it — not a competing framework. IMRT (`docs/IMRT_IMPLEMENTATION_SPEC.md`)
embeds into RDA conservatively in most rows, with one declared exception (IMRT's `Z` collapsing
RDA's separated `N_int`/`Z_∂` roles — a Deformation, not a Synthese, per RDA's own Prinzip 19.3).
SSKΩ-0..9 (`docs/OMEGA_CORE_CONFORMANCE_SPEC.md`) is re-classified as a staged conformance ladder,
structurally analogous to RDA's own RDA-0..RDA-6 — not a fourth competing axiom set. Neither
monograph is committed to this repository; both are cited by title in `docs/BCIK_IMPLEMENTATION_SPEC.md`.

`ssk-bcik` and the dead `ssk-imdf` closure/self-anchor machinery (`FourPiClosure`, `NullAnchor`,
`BcikCrossing`, and related types) are graded against the monograph's own H-instance/F-instance
discipline rather than renamed or given a new numbered ladder. Per-app traffic attribution — the
trigger for this work — is modeled as the first deferred consumer of the wired spine, not built
before it (see `docs/BCIK_IMPLEMENTATION_SPEC.md` Teil VII for the staged path).

## Rationale

This codebase had accumulated three apparently-competing formal vocabularies (IMRT's A1–A10, SSKΩ's
0–9, and now RDA/BCIK) with no stated relationship, risking a fourth incompatible layer every time a
new theory document was read against the code. RDA's own Anhang D already defines the pattern for
embedding external frameworks as conservative profiles (it lists SAA, QOFC, ADAMANT, LOOM); treating
IMRT and SSKΩ this way, once, closes that drift permanently rather than re-litigating it per
document. Separately, this codebase has now independently hit "built, tested, never reachable from
a real entry point" three times in one working session (`ssk-stitch`'s evidence flags, the P1 store
lockdown, and the entire `ssk-imdf` theory surface) — the decision to model BCIK as a spine wired
*before* any new per-app work, rather than the reverse, is a deliberate correction against repeating
that pattern a fourth time.

## Consequences

- `docs/BCIK_IMPLEMENTATION_SPEC.md` is the authoritative source for how RDA, BCIK, IMRT, and SSKΩ
  relate; future theory documents are expected to state their embedding relative to RDA rather than
  introduce a parallel axiom set.
- Implementation work proceeds in the staged order S0 (this modeling pass) → S1 (wire the existing
  dead `ssk-imdf`/`ssk-bcik` machinery, zero new concepts) → S2 (repair `ssk-bcik`'s own named
  defects) → S3 (split `NullAnchor` into genuine `N_int`/`Z_∂`) → S4 (per-app `AppAttribution` typing)
  → S5 (marker-source staging) → S6 (kernel-verified marker, if separately committed). No stage may
  be skipped ahead of the ones it depends on.
- Per-app steering does not reach Proxifier parity until S6 (a signed WFP ALE callout) is separately
  committed; until then, product copy claiming that parity remains a known, tracked overclaim
  (`docs/BCIK_IMPLEMENTATION_SPEC.md` Teil V §20).
