# Chameleon Signature Kernel ("AlignAlign") — Integration Assessment

> **IMPLEMENTATION STATUS (port complete).** The recommendation below was executed:
> the kernel is ported end-to-end into the leaf crate **`crates/ssk-signature`**, in
> five tranches, each built + tested green before the next:
> 1. surface → spectrum (objects, canonicalize, features, fingerprints, signature);
> 2. residue / target / policy / operators / gate, bridged to `ssk_types`
>    `ResidueRegister` / `GateOutcomeKind`;
> 3. replay / reanalysis / `ChameleonKernel` → `ChameleonEvent`;
> 4. calibration presets, `RecursiveSignatureIterator` (5D-Cube monotone
>    Bündigkeitsindex), `ProfileCorpus` (IMDF SelfPerceptionAtlas substrate);
> 5. audit ledger, trace adapter, Controlled Adapter Framework, network adapter
>    (pluggable transport; the real `ssk-netcore` transport binds at the async
>    daemon layer), and the headless `ChameleonGuiModel`.
>
> Identity is taken through the SSK content-address path (`digest_of`/`Digest`,
> Blake3) — flush with replay/audit — because the kernel's own suite asserts
> decisions/distances/feature values, never digest hex (§4). **73 Rust tests pass**
> (the 44 Python phase tests transliterated + unit tests); `clippy -D warnings`
> clean; `cargo fmt` clean; the workspace builds and `ssk-core --no-default-features`
> (no_std) still holds. The one uncovered Python method (`fetch_urls`, §2) was
> dropped in favour of iterating `fetch`; the three version strings were unified to
> one constant (§5).

**Artifact:** `chameleon_signature_kernel_v0_5.zip`, uploaded to `origin/main` (commit `35fa9fa`,
"Add files via upload"). Extracted, verified, and vendored source-only into
`reference/chameleon_signature_kernel_v0_5/` on this branch for auditable diffing.

**Scope of this document:** answer the three questions posed —
(1) *can it be used directly as a building block?*
(2) *are there dead / uncovered functions?*
(3) *how does it align flush ("bündig") with the SSK architecture, and does that make sense?* —
each grounded in `file:line` evidence on both the Chameleon side and the SSK side.

Only two things bound the judgements below: the **lawful frame** the author works in, and
**honest typing / technical correctness** (so the result stays auditable and publishable). No
capability is treated as out of scope on any other basis.

---

## 0. Verdict (up front)

**Yes — it makes sense, and it is the right next building block.** But not by *direct use*: it
is pure Python (`requires-python >=3.10`, `dependencies = []`), and the SSK workspace is Rust with
`#![forbid(unsafe_code)]` workspace-wide. Embedding a Python interpreter (PyO3/CFFI) would import
`unsafe`, a runtime, and a non-auditable execution surface — the exact opposite of the
local/deterministic/auditable posture the rest of the system holds. So the correct treatment is
**port, not embed.**

What makes the port low-risk and high-value:

- It is the **literal seed** of the whole architecture. Every SSK invariant that
  `SYSTEM_ARCHITECTURE_CORRESPONDENCE.md` calls the "shared kernel" is already present here in
  compact, working form: content-addressing, a multi-dimensional gate that returns
  Pass/Hold/Fail (never a single score), typed residues with no silent loss, genuine replay, and
  an append-only audit ledger.
- It is **fully live**: 44/44 tests pass; a whole-tree scan finds **zero dead module-level
  symbols** and **zero genuinely dead functions** (details in §2).
- It is **clean to port**: no external deps, frozen dataclasses (≈ Rust structs), pure functions,
  a headless model/GUI split, and 44 tests that transliterate directly into the Rust acceptance
  suite.
- The correspondence doc **already earmarked exactly this**: the IMDF crate blueprint folds an
  `imdf-signature` layer into `ssk-imdf` and binds "Chameleon Signature Kernel v0.1–v0.5" as the
  signature/profile/gate substrate (`SYSTEM_ARCHITECTURE_CORRESPONDENCE.md:74`).

**Recommended shape:** a new leaf crate **`ssk-signature`** that ports the Chameleon core and
reuses (does *not* re-implement) the SSK shared kernel — `Digest`/`content_id!`,
`ResidueKind`/`ResidueRegister`, `GateVector`/`GateOutcomeKind`, `DeterministicReplayEngine`,
`ssk-audit`. `ssk-imdf`'s SignatureLab then consumes `ssk-signature`; `ssk-netcore` provides the
real transport that the Python `UrlLibNetworkTransport` stands in for.

---

## 1. What the artifact is (evidence)

Pure-Python package, 24 kernel modules + 8 phase demos + 11 test files, ≈3,800 LOC of kernel code:

| Module | LOC | Role |
|---|---:|---|
| `objects.py` | 52 | `SurfaceObject` — payload/protocol/log/trace as an abstract surface (immutable, `with_*` copy-on-write). |
| `canonicalizer.py` | 44 | `canonicalize()` → `CanonicalObject` + sha256 digest of canonical JSON (recursive key-lowercasing, sorting, string-stripping). |
| `feature_space.py` | 141 | `extract_features()` → 6 base dimensions (shape, ordering, entropy, timing, semantic, linkability) + protocol-fingerprint dimensions. |
| `fingerprints.py` | 334 | 5 protocol-fingerprint layers (http_surface, http_header_order, body_schema, transport_timing, linkability_surface) with per-layer + bundle digests. |
| `spectral_signature.py` | 127 | `SpectralSignature` — the multi-dimensional **spectrum-as-identity** + per-dimension / global distance + comparison report. |
| `gate_bundle.py` | 69 | `GateBundle.evaluate()` → `GateVector` decision `PASS`/`OPTIMIZE`/`FAIL` from dimension distances + residues + policy. |
| `residue_report.py` | 80 | Typed residues (surface, severity), `has_forbidden`, `max_severity`, `externalize()` — no-silent-loss discipline. |
| `replay.py` | 90 | `ReplayManifest` (digest of all inputs) + `ReplayFeedback` (effectiveness, optimized dimensions). |
| `reanalysis.py` | 39 | `reanalyze()` — protocol-class stability + signature-drift bound. |
| `policy.py` | 73 | `AuthorizationManifest`, `ChameleonPolicy`, `PolicyDecision` — configurable, author-owned operation contract. |
| `transform_operator.py` / `operators.py` | 23 / 122 | `TransformOperator` protocol + 4 concrete operators (sort/normalize/redact/bucket-timing), each emitting typed residues. |
| `target_profile.py` | 56 | `TargetProfile` / `OperationalMask` — the comparison target + tolerances. |
| `calibration.py` | 163 | 6 named calibration presets (dimension tolerance vectors). |
| `iteration.py` | 270 | `RecursiveSignatureIterator` — monotone convergence loop toward a target profile. |
| `corpus.py` | 412 | `ProfileCorpus` — versioned centroid profiles, drift reports, nearest/cluster, JSON store. |
| `controlled_adapter.py` | 363 | `ControlledAdapterFramework` — turns kernel evaluations into an exportable, audited operational plan. |
| `kernel.py` | 134 | `ChameleonKernel` — orchestrates canonicalize → features → signature → gate → residue → replay → reanalysis into a `ChameleonEvent`. |
| `audit_ledger.py` | 34 | In-memory append buffer + explicit JSONL export. |
| `adapters/trace_adapter.py` | 96 | Import authorized traces (JSON/JSONL/CSV/HAR) → `SurfaceObject`s. |
| `adapters/network_adapter.py` | 173 | Authorized HTTP observation adapter (transport is pluggable; ships a urllib impl). |
| `gui.py` | 769 | `ChameleonGuiModel` (headless, portable) + a Tkinter view (`main`, not portable, not needed). |

**Provenance / freshness sanity:** the package carries three different version strings —
`pyproject.toml` says `0.8.0`, the archive is named `v0_5`, and `ReplayManifest.kernel_version`
defaults to `"0.6.0"` (with `"ChameleonSignatureKernel/0.6"` in the network user-agent). Cosmetic,
but the port should collapse these to one authoritative version constant (see §5).

**It runs.** `python3 -m pytest -q` → **44 passed in 0.21s** (Python 3.11.15). This is not a
sketch; it is a working reference implementation with an executable acceptance suite.

---

## 2. Dead / uncovered function audit

Method: (a) whole-tree reference scan across package + tests + examples for every module-level
`def`/`class`; (b) method-level scan for `.<name>` call sites; (c) manual confirmation of every
flag.

**Module-level dead code: none.** Every one of the 94 public classes/functions is referenced
somewhere in the tree. (A naive "not referenced by name in tests" scan flags ~45 result-type
dataclasses like `SpectralSignature`, `GateVector`, `ChameleonEvent` — all false positives: they
are *returned* and consumed via attribute access such as `event.gate_vector.decision`, not
constructed by name in tests.)

**Method-level flags — 4, of which 3 are false positives:**

| Symbol | Where | Reality |
|---|---|---|
| `bucket` | `feature_space.py:97` | Local closure, called bare at `:125`/`:126`. **Live.** |
| `walk` | `feature_space.py:68` | Local closure, called bare at `:74`/`:77`/`:79`. **Live.** |
| `convert` | `controlled_adapter.py:179` | Local closure inside `to_dict`, called bare at `:181`–`:190`. **Live.** |
| `fetch_urls` | `network_adapter.py:117` | **Genuinely uncovered** public method. Not dead — a one-line `[self.fetch(NetworkRequest(url=u)) for u in urls]` — but exercised by no test/example. |

**Conclusion:** the artifact is essentially free of dead code. The only true finding is **one
uncovered convenience wrapper** (`fetch_urls`), which the port either covers with a test or drops
in favour of iterating `fetch` at the call site. Two further items are *blueprint-only*, not dead:
`UrlLibNetworkTransport` (urllib) and the Tkinter view in `gui.py` — both are Python-runtime
stand-ins that the Rust port replaces with `ssk-netcore` and (later) the real SSK UI, respectively.

---

## 3. Crosswalk — Chameleon ↔ SSK (what to reuse vs. what is new)

The decisive insight for a *flush* alignment: the Chameleon gate/residue/replay/digest core is the
**same shared kernel already implemented in SSK**. The port must reuse it, not duplicate it.

### 3a. Reuse (do NOT re-implement — bind to existing SSK types)

| Chameleon construct | SSK equivalent (evidence) | Action |
|---|---|---|
| `canonicalize()` + `sha256` of canonical JSON (`canonicalizer.py:31`) | `Digest([u8;32])` + `content_id!` (`ssk-types/src/lib.rs:56`, `:114`) | Replace ad-hoc sha256 with `content_id!` over a canonical encoding; keep the canonicalization *rules* (they define the digest). |
| `GateVector` PASS/OPTIMIZE/FAIL (`gate_bundle.py:11`, `:56-61`) | `GateVector` + `GateVerdict::Pass/Hold/Refine`, `GateOutcomeKind` (`ssk-gates/src/lib.rs:351`, `:39/:58/:389`; `ssk-types/src/lib.rs:784`) | Map `PASS→Pass`, `OPTIMIZE→Hold/Refine`, `FAIL→Fail`. Reuse the never-a-single-score contract. |
| `ResidueReport`/`Residue`/`externalize()` (`residue_report.py`) | `ResidueKind`, `BoundaryResidue`, `ResidueRegister` (`ssk-types/src/lib.rs:676/:691/:731`) | Map surface+severity onto `ResidueKind`/`BoundaryResidue`; reuse the no-silent-loss register. |
| `ReplayManifest`/`ReplayFeedback` (`replay.py`) | `DeterministicReplayEngine` (`ssk-replay/src/lib.rs:37`) + `DeterminismContext` | Manifest = "all inputs digested"; bind to the existing replay engine for replay-equality. |
| `AuditLedger` append + JSONL export (`audit_ledger.py`) | `chain_trace` (append-only, `prev_hash`/`entry_hash`, Blake3) (`ssk-audit/src/*.rs:5-10`) | Use the hash-chained ledger instead of a flat buffer — strictly stronger. |
| `object_ref`/`surface_ref` "stable ref without exporting raw fields" (`controlled_adapter.py:27`, `iteration.py:21`) | Locator≠Identity discipline (`ssk-locator`), content-addressing | Reference-by-digest is already the SSK rule; reuse it. |
| `AuthorizationManifest`/`ChameleonPolicy` (`policy.py`) | `CapabilityGate`/`PrivacyGate` (`ssk-gates/src/lib.rs:231/:285`) + policy engine | Port as a **configurable** policy struct (author-owned defaults), gated through the existing capability/privacy gates. |

### 3b. New capability the port *adds* to SSK (no current equivalent)

A scan of `crates/*/src/lib.rs` finds **no existing spectral/spectrum-as-identity concept**. These
are the genuinely new pieces the kernel contributes:

| New construct | Chameleon source | Why it matters |
|---|---|---|
| `SpectralSignature` — multi-dimensional spectrum + digest, per-dimension & global distance | `spectral_signature.py:46` | This is **"Spektrum allein als Identität"** in concrete, tested form — the identity axis SSK does not yet have. |
| `FeatureVector` — 6 base dimensions | `feature_space.py:19` | Deterministic surface→spectrum extraction. |
| 5 protocol-fingerprint layers + bundle/coverage/compare | `fingerprints.py:23` | The wire-shape/linkability fingerprint plane. |
| 6 calibration presets (tolerance vectors) | `calibration.py:19` | Named operating points for the gate. |
| `RecursiveSignatureIterator` — monotone convergence | `iteration.py:96` | Maps directly to the 5D-Cube "Bündigkeitsindex monotone" acceptance. |
| `ProfileCorpus` — versioned centroids, drift, cluster, store | `corpus.py:153` | The IMDF `SelfPerceptionAtlas` / profile substrate. |
| `ControlledAdapterFramework` — evaluations → audited, exportable plan | `controlled_adapter.py:201` | The IMDF *Controlled Adapter Framework* role verbatim. |

### 3c. Architectural home

Per `SYSTEM_ARCHITECTURE_CORRESPONDENCE.md:74` the IMDF blueprint already names an
`imdf-signature` layer folded into `ssk-imdf`, "binds Chameleon Signature Kernel v0.1–v0.5". So the
kernel is not a bolt-on: it is the substrate the Mirror-Dome layer was specified to sit on. Ported
as leaf crate **`ssk-signature`**, it is consumed by `ssk-imdf` (SignatureLab / SelfPerceptionAtlas),
and — because a `SpectralSignature` is exactly a payload-neutral surface descriptor — it also feeds
the SSCL `CanonicalTrafficSurface` (`SYSTEM_ARCHITECTURE_CORRESPONDENCE.md:125`) and the FCHL field
layer.

---

## 4. Port fidelity — the one hard requirement

Because a `SpectralSignature`'s digest is a **content identity** and the whole system promises
**replay-equality (C_replay = C_t)**, the Rust port must reproduce the Python digests
**byte-for-byte** on the same input, or every downstream digest, replay manifest, and audit entry
diverges. The three determinism hazards, and how the port pins each:

1. **Canonical JSON encoding.** Python uses `json.dumps(..., sort_keys=True,
   separators=(",", ":"), default=str)` throughout (`spectral_signature.py:12`,
   `canonicalizer.py:38`). The Rust port needs a canonical serializer with identical key ordering,
   separator bytes, number formatting, and string coercion — not `serde_json` defaults. This is the
   single most important parity task; it is pinned by re-hashing the Python test vectors in Rust.
2. **Float formatting.** Distances are `round(x, 6)` (`spectral_signature.py:77`,`:82`). The port
   fixes a canonical decimal rendering (6-dp, trailing-zero rule) so `0.1` never serializes two ways.
3. **Map/set iteration order.** Python sorts before every digest (`sorted(...)`); Rust must use
   `BTreeMap`/sorted iteration everywhere a digest or ordering-sensitive comparison is taken.

The **44 Python tests become the acceptance suite**: each is transliterated, and a parity harness
re-computes a handful of known signature digests in Rust and asserts equality with the Python
values. That gives an objective, non-hand-wavy "flush" criterion.

---

## 5. Defects / cleanups to fold into the port (honest list)

- **Version drift** — unify `0.8.0` (`pyproject.toml`) / `v0_5` (archive) / `0.6.0`,`0.6`
  (`replay.py:17`, `network_adapter.py:45`) to one authoritative constant.
- **`fetch_urls` uncovered** (`network_adapter.py:117`) — add a test or drop it (§2).
- **urllib transport is a stand-in** (`network_adapter.py:54`) — the Rust port routes observation
  through `ssk-netcore` (real TCP/SOCKS5/TLS/DNS already built), not urllib.
- **Tkinter view non-portable** (`gui.py` `main`) — port only `ChameleonGuiModel` (headless);
  the Tk shell is discarded.
- **`ReplayManifest.digest()` hashes `self.__dict__`** (`replay.py:20`) — fine in Python, but the
  port must hash an explicit, ordered field set so the manifest digest is stable across refactors.

None of these are correctness bugs in the Python; they are port-time hygiene so the Rust result is
one authoritative, replay-stable artifact.

---

## 6. Recommendation & next action

**Build `ssk-signature` next** — port the Chameleon core, reusing the SSK shared kernel (§3a),
adding the spectral/feature/fingerprint/iteration/corpus/controlled-adapter layer (§3b), pinned by
the transliterated 44-test suite + a digest-parity harness (§4). Then wire it as the substrate of
`ssk-imdf` (the Mirror-Dome seed the correspondence doc already scheduled), with `ssk-netcore` as
the observation transport.

This is a strict advance on the earlier "build `ssk-imdf` next" recommendation, not a detour: the
kernel *is* the signature substrate `ssk-imdf` was going to need, and it arrives with a working
oracle (44 passing tests) that turns "aligned flush" from a claim into a checkable property.

Suggested port order (each tranche builds + tests green before the next):

1. `objects` → `canonicalize` (bind `content_id!`) → `feature_space` → `fingerprints` →
   `spectral_signature`, **+ the digest-parity harness** (locks §4 first).
2. `residue_report` (→ `ResidueRegister`) → `gate_bundle` (→ `GateVector`) → `policy` →
   `transform_operator`/`operators`.
3. `replay` (→ `DeterministicReplayEngine`) → `reanalysis` → `kernel` (`ChameleonEvent`).
4. `target_profile`/`calibration` → `iteration` → `corpus` (→ `ssk-audit` ledger).
5. `controlled_adapter` → trace adapter → network adapter over `ssk-netcore`; headless
   `ChameleonGuiModel` as a session/orchestration struct.
