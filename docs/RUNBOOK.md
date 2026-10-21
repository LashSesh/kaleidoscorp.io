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
2. Ensure `version: 5`, `fail_closed=true`, `runtime.strict_mode=true`.
3. If legacy format is detected, migrate and re-validate.
4. Restart only after lint success.

## Daemon activation safety (2026-09-22)

`sskd` now retains the startup configuration result. An unreadable or invalid
`SSK_CONFIG_PATH` leaves IPC available in `ConfigInvalid`, but activation returns
`CONFIG_INVALID` (CLI exit 10) without a network attempt. `ssk --json status`
reports the cause; the IPC `RunDoctor` response also includes a `config` check.
Fix the file/path and restart `sskd`; `deactivate` does not clear this error.
Routing now uses the validated v5 profile and adapter configuration. New and
migrated configurations deny all connections until explicit rules are added.
There is no reload: a configuration edit takes effect after a daemon restart. The
`ingress` section is validated at load (a typo or an out-of-range value makes the
whole file invalid), but this build opens no listener yet; once it does, a restart
will bring the proxy back disarmed unless `ingress.arm_on_start` is true.
See [routing and OpenVPN status](ROUTING_AND_OPENVPN_STATUS.md) for migration,
configuration examples and the unavailable OpenVPN adapter.

Each admitted network attempt appends `DispatchPending` before connecting and a
terminal `Dispatched` or `FailClosed` record afterwards. Only a durably recorded
successful connection can produce `Protected`. An unreadable/unwritable ledger
returns `LEDGER_IO_FAILED` (CLI exit 13); a corrupt chain returns
`AUDIT_CHAIN_BROKEN`. If result persistence fails after connect, the new socket is
closed and no `Protected` event is published. Replacing a session first closes
the previous one, so a failed replacement cannot leave it hidden behind a failed
status. A failed ledger read during a status request also closes any held session.

Keep an incident copy of the existing ledger before recovery. Check the state
directory, free space and permissions, and investigate integrity failures. Do not
delete the ledger just to clear the error. `DispatchPending` without a terminal
record means the result is unknown (for example after a crash), never success.
Entry sequences continue from the persisted ledger length after restart.

These checks protect the daemon's own connection. They neither engage the
system-wide kill switch nor establish application-traffic coverage. A broker
warning remains visible in `last_error` or, when an activation error has priority,
in its `next_steps`. Audit verification still establishes prefix integrity; an
independently protected checkpoint and continuous storage-health monitoring are
separate work.

## Capability Mismatch
1. Inspect negotiated capabilities and required baseline:
   - `gate-vector-12`
   - `replay-v1`
2. Align peer/local capability sets.
3. Keep strict mode enabled.
4. Reattempt handshake and verify deterministic replay.
