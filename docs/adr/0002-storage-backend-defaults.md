# ADR 0002: Storage Backends

## Decision
Use `MemoryBackend` as default runtime backend and `FileLedgerBackend` as optional persisted backend.

## Rationale
Memory backend keeps MVR deterministic and low-friction. File ledger enables auditability and persistence when enabled.

## Consequences
Core workflow is easy to test locally while preserving migration path to persisted ledgers.
