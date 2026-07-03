# Architecture

The workspace follows the SSK Ω separation model:

- `ssk-types` / `ssk-core`: deterministic, typed domain foundation
- `ssk-scheduler`: fixed-point deterministic phase ticks
- `ssk-bcik` + `ssk-gates`: fail-closed crossing and gate enforcement
- `ssk-tensor`: append-only hash-chained stitch persistence
- `ssk-replay`: deterministic replay diff verdicts
- `ssk-runtime`: run_once orchestration of the full spine
- `ssk-cli`: operational entry points

Data path: Intent -> Orbit -> Locator -> BCIK -> GateVector -> Tensor -> Focus -> Replay.
