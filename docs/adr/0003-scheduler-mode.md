# ADR 0003: Scheduler Determinism

## Decision
Default scheduler mode is deterministic fixed-point progression; seeded mode is represented in scheduler state for replay consistency.

## Rationale
Determinism is mandatory for replay verification and conformance obligations.

## Consequences
Decision core avoids wall-clock/RNG nondeterminism and is replay-stable.
