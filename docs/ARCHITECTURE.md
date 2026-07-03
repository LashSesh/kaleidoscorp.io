# Architecture

The workspace follows the SSK Ω separation model:

- `ssk-types` / `ssk-core`: deterministic typed domain foundation
- `ssk-scheduler`: fixed-point deterministic phase ticks
- `ssk-bcik` + `ssk-gates`: fail-closed crossing and gate enforcement
- `ssk-tensor`: append-only hash-chained stitch persistence
- `ssk-replay`: deterministic replay diff verdicts
- `ssk-interop`: version/capability negotiation + strict canonical decode guards
- `ssk-config`: versioned fail-closed policy/config schema + migration baseline
- `ssk-runtime`: run orchestration and deterministic observability events
- `ssk-cli`: operator UX (`doctor`, `explain`, `--json`, config tooling)

Data path: Intent -> Orbit -> Locator -> BCIK -> GateVector -> Tensor -> Focus -> Replay.

Observability path: Runtime event envelope (`run_id`, `replay_id`, `seeded`, `epoch`) + local metrics counters (`run_count`, `gate_failures`, `replay_drifts`).
