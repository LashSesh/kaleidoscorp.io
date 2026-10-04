# ADR 0008: The Flow Path Owns the Per-Connection Decision; the Decision Core Does Not

## Decision

`ssk-netadmin`'s `FlowDescriptor → PolicyEngine::evaluate → RouteOrchestrator::plan →
RouteExecutor::connect` spine is the per-connection decision path, and the only one. `sskd` does not
call `ssk_runtime::run_to_outcome` and will not. The daemon's dependency on `ssk-gates` — which today
exists solely so `ssk-config`'s `HypercubeConfig.axes` can reuse `ssk_gates::pch::Axis`
(`crates/ssk-config/Cargo.toml:9`, `crates/ssk-config/src/lib.rs:200-212`) — is severed by relocating
that enum into `ssk-types`.

The routing configuration schema — adapters, ordered policy rules with CIDR / port-range /
process-path criteria, profiles — is new work, owned by exactly one config crate. There will not be
a second config loader. `LoadedConfig` must reach `Supervisor::new`; today the daemon loads it and
discards it (`crates/ssk-daemon/src/main.rs:246-250` emits one `tracing::info!` and drops the value).

Admission becomes enforced by construction rather than convention: `DataPlane::connect_route`
(`crates/ssk-netcore/src/data_plane.rs:34`) comes to require an `AdmissionToken` with no public
constructor and no `Serialize`, minted only where `RouteCandidate.requires_attestation` has been
discharged. The guarantee this buys is precise and bounded: no crate outside the token's defining
crate can dispatch without one. `docs/BCIK_IMPLEMENTATION_SPEC.md` §25's VC10 (Import-Gate as
fail-closed admission controller) is re-targeted onto this seam.

Stages S4 (typed `AppAttribution`) and S5 (marker source; `Hold`/`FailClosed` on marker-less flows)
of `docs/BCIK_IMPLEMENTATION_SPEC.md` §24 move into the product workspace and land jointly with
ingress, expressed as `PolicyAction` values rather than `RunOutcome` variants. S2 and S3a survive
verbatim as decision-core work off the product critical path. S3b (`epsilon_stitch` calibration) is
resequenced after ingress, since it needs real captured traffic that does not yet exist. S6 is
unchanged. The unnumbered stage logged at §24a — "connect `sskd`'s supervisor to this decision
pipeline" — is retired with the reason recorded below.

## The two questions this ADR first left open

Both questions this ADR originally deferred — extracting the decision core into a sibling workspace,
and deleting the six crates flagged as zero-consumer — are now decided. They are recorded here rather
than in a new ADR because neither reverses anything above; both close an item this decision opened.

**No workspace split.** The decision core stays in this workspace. Three reasons. First, the split
would remove the shipped `ssk connect` and `ssk replay-verify` subcommands
(`crates/ssk-cli/src/main.rs:225`, dispatched at `:813`) from the product — a product-surface
reduction, not hygiene. Second, the Consequences below deliberately leave open whether the
identity-crossing spine returns to the product, pending three measurements that need real captured
traffic that does not exist yet; moving the core out now would prejudge that question in the
direction of "no". Third, the invariant the split would buy — the decision core cannot reach the
shipping `sskd` binary — is bought instead by a mechanical guard, at a fraction of the cost and
reversibly. That guard is `crates/ssk-daemon/tests/dependency_closure.rs`: it reads cargo's own
resolver output (`cargo metadata`, `normal`/`build` edges only, no platform filter, so both CI legs
agree) and asserts two things. `decision_core_stays_out_of_the_daemon` fails if any of `ssk-bcik`,
`ssk-core`, `ssk-focus`, `ssk-gates`, `ssk-imdf`, `ssk-locator`, `ssk-runtime` or `ssk-stitch`
becomes reachable, and prints the actual edge chain.
`daemon_dependency_closure_is_the_set_adr_0008_recorded` pins the 16-crate closure the Consequences
below state as fact, so a *renamed* decision-core crate re-entering still fails even though the
deny-list would no longer match its name. Verified by
forcing the failure: re-adding `ssk-gates` to `crates/ssk-config/Cargo.toml` makes both tests fail,
the first naming the chain `ssk-daemon -> ssk-config -> ssk-gates`. It needs no CI change —
`build_test` already runs `cargo test --workspace` on both `ubuntu-latest` and `windows-latest`.

**Five of the six flagged crates are kept; they are deferred work, not dead code.** They are
`ssk-topology-scalpel`, `ssk-host-cells`, `ssk-funnel-dag`, `ssk-profile-manifold` and
`ssk-delivery`, and each is phase-assigned and gate-named in the repository's own planning
documents: `FCHL_MPK_INTEGRATION_STRATEGY.md` schedules the scalpel planner as P3 with the "Scalpel
Gate Test, negative" acceptance (`:215`, object row `:105`), host-cells and funnel-dag as P4, Band B,
gated on a capture source that does not exist (`:216`, rows `:107`/`:108`, `:42`), and
ProfileManifold as P6, Band C, `[SSCL-UNVERIFIED]` (`:218`, row `:112`);
`SYSTEM_ARCHITECTURE_CORRESPONDENCE.md` places them in named integration blocks — F (`:270`),
P (`:268`), S/D (`:272`), X (`:273`) — and describes each at `:22`, `:24`, `:29`, `:32`, `:42`.
`ssk-host-cells` is additionally conformance-graded **Realized** against IMRT axiom A1
(`docs/IMRT_IMPLEMENTATION_SPEC.md:248`) with gap G7 discharged by a named passing test (`:334`), and
it is not in fact consumer-free: `crates/ssk-funnel-dag/Cargo.toml:15` depends on it and
`crates/ssk-funnel-dag/src/lib.rs:195-199` makes a node live only if `HostCellPlane::is_active`
agrees its bound cell survives. All 35 tests across the five pass (measured: 9+3+5+5+6+5+2 across
their unit and proptest targets). The real defect was never the crates; it was that this status
lived only in two root-level strategy documents, so a reader of a crate saw an unreferenced crate and
reasonably
concluded it was abandoned — a conclusion drawn about all five during the investigation that
produced this section. What changed instead: each of the five gained a `## Status` stanza in its
`//!` header naming its band, phase, gate, and the document line where that is decided.
`ssk-delivery`'s stanza is deliberately weaker than the others and says so, because its evidence is:
it has no numbered phase and no named acceptance test anywhere, and the Block S/D rows that schedule
it (`SYSTEM_ARCHITECTURE_CORRESPONDENCE.md:234`, `:254`, `:272`) name a crate `ssk-package` rather
than this one.

**`ssk-sim` is retired.** It is deleted from `crates/` and from the `members` list in the workspace
`Cargo.toml`; the workspace goes from 45 crates to 44 and `Cargo.lock`'s entry disappears on the next
build. It is 17 LOC — one struct and one function whose `evaluate()` reads `residues.len()` and
`stitch.is_some()` off a `RuntimeOutcome`, both of which any caller can read directly. No manifest in
the workspace depended on it, it had no tests, and its declared `sim` feature gated nothing: a
repository-wide search for `feature = "sim"`, `features = ["sim"]` and `--features sim` returns no
hits and the crate contained no `#[cfg]` at all. Its two documentation rows (`README.md`'s crate map
and `docs/DESKTOP_CLIENT_ARCHITECTURE.md` §B.3, which graded it `[2]` stub-level — the lowest grade
in that table, on the 0–7 ladder of `ARCHITECTURE_COMPLETION_SPEC.md:7` where level 4 is a tested
artifact) are removed with it. This is a retirement, not a deferral: it is not renumbered, not
assigned a band, and nothing replaces it. The line being drawn is between deferred-with-a-plan and
never-planned, not between used and unused — which is exactly why the other five stay. To restore
it, recover the two files and re-add `"crates/ssk-sim",` to `members`; it depended only on
`ssk-types` and built standalone, so nothing else is needed.

## Rationale

`ConnectionIntent` (`crates/ssk-types/src/lib.rs:622-628`) has no field that can hold a destination
host or port; `FlowDescriptor` (`crates/ssk-netadmin/src/flow.rs:31-42`) does. A decision type that
cannot name where a packet is going cannot be the per-flow decision type. That is arity, not
preference, and it closes a question that had been logged as open. Wiring the decision core into
per-connection traffic would instead require fabricating a `CoreNode`, a `MirrorFacet` and a
`CapabilityWitness` per TCP connection — exactly the synthetic evidence ADR 0007 and this project's
standing discipline exist to prevent.

The sharper finding is an inversion nobody had stated: the system that owns the actuator has no
configuration, and the system that owns the entire configuration has no actuator.
`crates/ssk-config/src/lib.rs` (1,164 LOC) is the daemon's only config crate and contains zero
occurrences of `adapter`, `destination`, `socks` or `app_prefix`; even its `Policy` type is
`{name, fail_closed, gate_profile}` (`:551-554`). Meanwhile `ssk-netadmin`'s live decision path runs
on a `FlowDescriptor` whose `app_id`, `protocol` and `risk_level` are the literals `"sskd-activate"`,
`Tcp` and `Low` (`crates/ssk-daemon/src/supervisor.rs:544-552`), against three rules hardcoded twice
(`supervisor.rs:177-218`, duplicated byte-for-byte at `crates/ssk-cli/src/main.rs:5356-5399`) — so on
the only path where a decision reaches a real socket, the answer is a constant `Allow → Direct`. The
engine runs; it decides nothing. The roadmap's own P4 exit criterion ("classified by a config-declared
rule, dispatched through a config-declared adapter", `docs/WINDOWS_PRODUCT_ROADMAP.md:664-666`) is
therefore blocked on a configuration surface that does not exist in any crate in the workspace —
before ingress is even reached. That is why severing the edge moves ahead of the ingress phase: it is that
phase's precondition, not tidying.

One measured number motivates the severance. `cargo tree -p ssk-daemon -i <crate>` shows that
`ssk-gates` (1,492 LOC before this ADR's own severance work moved `Axis` out of it; 1,484 after),
`ssk-imdf` (4,447), `ssk-core` (580), `ssk-locator` (467), `ssk-bcik` (378) and `ssk-focus` (270) —
7,626 LOC total (re-measured post-severance; corrected from an earlier 7,634 figure taken before the
`Axis` move itself shrank `ssk-gates` by 8 lines) — reach the shipping daemon binary by exactly the
one `ssk-config → ssk-gates` edge and no other. No decision logic among them ever executes in `sskd`;
the only code touched at runtime is `ssk_gates::pch::Axis`'s derived `Deserialize`/`Default` during
config load.

Four documents (`README.md:65-90`, `README.md:322-326`, `ARCHITECTURE.md:37-44`,
`NETADMIN_SPEC.md:37-41`) draw a data-flow edge from `ssk-runtime` into `ssk-netadmin` that has never
existed in either direction, and `SYSTEM_ARCHITECTURE_CORRESPONDENCE.md:110-123` (repository root)
omits `ssk-netadmin` from its layer stack entirely. Those diagrams are the most likely source of the
confusion this decision resolves; correcting them is part of it.

## Consequences

- `sskd`'s dependency closure drops from 22 crates to 16, shedding 7,626 LOC that never executes any
  decision logic. Verified: `cargo tree -p ssk-daemon --edges normal` now lists exactly 16 crates and
  `cargo tree -p ssk-daemon -i <crate>` errors as "did not match any packages" for each of `ssk-gates`,
  `ssk-bcik`, `ssk-imdf`, `ssk-core`, `ssk-focus`, `ssk-locator`.
- `README.md:42`'s "12-gate enforcement system" ceases to be a product capability bullet; it is
  decision-core-only, and where it is reachable roughly nine of twelve predicates are unconditionally
  satisfied (`docs/WINDOWS_PRODUCT_ROADMAP.md:186-194`).
- Building the routing configuration schema is re-costed upward: it is new construction, not an
  extension of an existing surface, because there is no existing surface to extend.
- `RouteCandidate.requires_attestation` (`crates/ssk-netadmin/src/route.rs:175-177`) is currently
  discarded before dispatch (`supervisor.rs:556-558` maps the candidate down to its `RouteKind`, and
  `RouteExecutor::connect` takes `&RouteKind`, `crates/ssk-netcore/src/executor.rs:114-116`). This is
  a **latent** fail-open, not a live one — the three hardcoded rules never construct
  `RequireAttestation` — and it becomes live the moment an operator can write such a rule. It is
  therefore cheaper to close before the configuration schema lands than after.
- Whether the identity-crossing spine returns to the product is deliberately left open, and is decided
  after ingress on three measurements that cannot be taken today: per-decision latency at concurrency,
  tensor growth under load, and a real attribution coverage rate. Re-homing the decision core's three
  portable properties — replay-manifest determinism, the typed `BoundaryResidue` taxonomy, and
  tamper-evident materialization — onto `FlowRecord`/`PolicyDecision` proceeds independently of that
  answer, since all three live in `ssk-types`/`ssk-audit`/`ssk-tensor` and `ssk-netadmin` already
  depends on `ssk-tensor`.
- Per-app steering still does not reach Proxifier parity until S6; ADR 0007's tracked overclaim stands
  unchanged.


## Addendum 2026-09-22: OpenVPN host components

The resolved daemon workspace closure intentionally grows from 16 to **17**: the
new edge is `ssk-winhost -> ssk-vpnctl`. The Windows host uses the portable
validated profile type and `ChildProcess` supervision contract for protected
profile storage and OS job containment. The crate has no workspace dependencies,
and none of the eight denied decision-core crates re-enters the closure.

The flow path still owns admission; management/process status cannot grant egress.
No VPN launch IPC command is added in this step. The production host dependency
is explicit even while composition is pending, and the exact-closure test is
updated in the same change. Splitting the Windows library by binary is deferred;
the existing platform-neutral dependency guard remains enabled.
