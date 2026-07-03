# ADR 0004: std vs no_std

## Decision
Workspace defaults to `std`; foundation crates (`ssk-types`, `ssk-core`) are no_std-friendly and checked in CI.

## Rationale
Developer productivity is higher with std defaults, while preserving embedded/alloc portability for core logic.

## Consequences
Core model portability is maintained without sacrificing day-to-day ergonomics.
