# ADR 0006: Stage-2 Interop + UX Hardening

## Decision
Adopt a versioned interop layer (`ssk-interop`) with strict canonical decode defaults, explicit version/capability negotiation, and machine-readable error codes. In parallel, enforce versioned fail-closed configuration and a hardened CLI surface (`doctor`, `explain`, global `--json`, exit-class taxonomy).

## Rationale
The runtime core was deterministic and replay-ready but lacked a stable protocol contract and production-grade operator UX. Stage-2 closes that gap by making interoperability, startup policy validation, and incident diagnostics explicit and testable.

## Consequences
- Interop behavior becomes spec-backed and regression-testable.
- Operational usage becomes scriptable and safer by default.
- Future protocol/config evolution can proceed through versioned compatibility strategy.
