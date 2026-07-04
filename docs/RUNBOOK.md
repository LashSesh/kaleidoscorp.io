# Runtime Runbook

## Ledger Mismatch
1. Stop writes immediately.
2. Run `ssk --json verify-ledger --path <ledger>`.
3. Compare ledger head with replay manifest `trace_head`.
4. Restore last known good ledger segment.
5. Re-run replay verification before reopening writes.

## Replay Drift
1. Run `ssk --json replay-verify --valid-fixture true`.
2. Compare `run_id`, `replay_id`, `seeded`, `epoch` fields.
3. Verify handshake constraints (`docs/INTEROP_SPEC.md`).
4. If drift persists, isolate regression via deterministic tests and bisect.

## Corrupted Config
1. Run `ssk config lint --path <config>`.
2. Ensure `version=2`, `fail_closed=true`, `runtime.strict_mode=true`.
3. If legacy format is detected, migrate and re-validate.
4. Restart only after lint success.

## Capability Mismatch
1. Inspect negotiated capabilities and required baseline:
   - `gate-vector-12`
   - `replay-v1`
2. Align peer/local capability sets.
3. Keep strict mode enabled.
4. Reattempt handshake and verify deterministic replay.
