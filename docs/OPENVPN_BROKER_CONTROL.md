# OpenVPN broker control — 2026-09-22

The service now owns a separate VPN control domain and continuously polls its
held session on a dedicated worker. The CLI reaches it through the authenticated
Windows control pipe. This composes [secure preparation](OPENVPN_SECURE_START.md)
with explicit authorization, durable intent/result records, concurrency control,
idempotency, service shutdown and [explicit crash recovery](OPENVPN_RECOVERY.md). **It does not release HOLD, connect a tunnel,
change routes/DNS/firewall rules or grant application egress.** Configured VPN
activation still returns `OPENVPN_NOT_READY`.

## Commands and compatibility

The later [configuration installer](OPENVPN_CONFIGURATION_DEPLOYMENT.md) selects
profiles and grants together. The service locks/verifies the journal first, then
loads one matching snapshot for pipe admission, authorization and preparation.
Its committed digest prevents accidental fallback to revoked legacy permissions.
Pending deployment or configuration-restoration intent blocks this startup before
loading authorization. [Offline exact restoration](OPENVPN_CONFIGURATION_RESTORE.md)
can repair the committed document while preserving unresolved process state;
normal granted recovery remains required afterwards.

The explicit VPN-only wire version is 3. Both ends must select exactly version 3;
there is no fallback from a VPN request to a boundary command. Existing kill-switch
clients and envelopes remain version 1. Version 3 cannot adopt or release boundary
leases; disconnecting a VPN client does not stop the service-owned session.
The earlier VPN version 2 is rejected at handshake; update CLI and service together.
Existing schema-1 journals remain readable.
The CLI verifies that the server pipe belongs to LocalSystem before handshaking.
The service authenticates the actual pipe peer before reading any frame.

```powershell
ssk --json winhost vpn status company-managed
# Use the VPN revision returned by status, not a kill-switch state version.
ssk --json winhost vpn prepare company-managed --expected-revision 1
# After preparation completes, read its current revision before stopping.
ssk --json winhost vpn status company-managed
ssk --json winhost vpn stop company-managed --expected-revision 4
# Only after recovery_required, with a separate recover grant and fresh revision:
ssk --json winhost vpn recover company-managed --expected-revision 8
```

Revision values above are examples. `Accepted` means the intent was synchronized
to disk and queued; it does not mean preparation, stopping or recovery has completed. Poll
`status` for `prepared_held`, `idle`, `failed` or `recovery_required`. Each status
carries the revision, profile, operation ID, failure category, journal health and
whether OS exit was confirmed. No PID, secret, path or generic management command
is accepted from the client. `prepared_held` is historical status, not admission.

One profile occupies the worker at a time. A second prepare or a stop during
preparation returns `Busy`; preparation has bounded startup deadlines. Service
shutdown cancels preparation independently of pipe requests. Once a process is
held, `stop` requests graceful termination and continuous polling observes the
actual exit or escalates termination. An unconfirmed exit prevents replacement.
Idle status for another authorized profile redacts the previous profile and
operation while retaining the current revision for the next request.

For an uncertain transport result, reuse the printed `--operation-id` with a fresh
nonce (the CLI supplies one). Keys and nonces are bound to the authenticated SID;
the command, including profile, must match. A duplicate returns the **original
acceptance**, explicitly marked `Duplicate`; query status for the latest outcome.
Keys/nonces are retained for the service session, capped at 4,096 mutating attempts
without eviction. Status consumes no budget. Stale revisions and busy attempts
consume a nonce but do not claim an idempotency key. Reconnecting does not reset
the budget. Restart creates a new capability and replay window; idempotency is not
a cross-restart exactly-once guarantee.

## Protected authorization policy

An administrator must first provision the existing protected profile store and
approve the executable bundle and profile. This broker increment neither installs a VPN
distribution nor imports arbitrary `.ovpn` files. Before managed-configuration
migration, the legacy layout reads this additional policy file:

`%ProgramData%\ScorpioSync\state\openvpn-profiles\openvpn-control.json`

In the managed layout, the same policy object is the `policy` field of the whole
configuration document. The separate legacy file is ignored after the first
managed commit; see the configuration workflow linked above.

```json
{
  "schema": 1,
  "grants": [
    {
      "sid": "S-1-5-21-111-222-333-1001",
      "profile": "company-managed",
      "verbs": ["status", "prepare", "stop", "recover"]
    }
  ]
}
```

The SID is a syntactically valid example, not a default account grant. Every
verb/profile pair is explicit, including status. Neither administrator membership
nor a kill-switch grant grants VPN authority. Unknown/duplicate fields, duplicate
grants, invalid SIDs/profile IDs, unrecognized verbs, more than 128 entries or a
document above 32 KiB are rejected. An empty grant set grants nothing. Changes
take effect after service restart; there is no policy hot reload.

Directory and file confidentiality, reparse points and hardlinks are checked
through the production Windows probe. The policy read handle denies write/delete
sharing. Missing or unsafe policy/storage disables VPN control and leaves
kill-switch control independent. The pipe's admitted SID set is the union of both
domains (at most 64 distinct explicit clients); per-request authorization remains
separate. Interactive boundary diagnostics remain reachable when the boundary
policy is degraded. The VPN domain refuses a zero session token if OS randomness
failed; it never falls back to a predictable VPN capability.

## Durable journal and failure handling

The fixed `openvpn-control.journal` file lives beside the policy, with the same
confidential ACL checks. The host opens or claims it with `create_new`, verifies it
before writing, rejects hardlinks/reparse points and holds a file handle excluding
another writer or deletion for the service lifetime. No arbitrary journal path is
accepted through IPC. The host does not provision the profile directory at startup.

Records are length-prefixed strict CBOR with schema, sequence, previous hash,
BLAKE3 hash and a secret-free event/status. Client intents include the authenticated
SID and exact command; internal results, observations, boot and shutdown are marked
as service events and retain the operation ID. The journal orders events using
sequence and revision; it does not provide wall-clock timestamps. Hash chaining
detects corruption, sequence gaps and naive edits, not forgery, whole-file deletion
or tail rollback by an administrator who controls the protected store.

Every prepare/stop/recover intent is written and `sync_all` completes **before** the worker
can perform it. Results and lifecycle changes are appended separately. If an
intent cannot be stored, no new effect starts. A result/observation write failure
latches an audit fault, rejects further mutations and terminates any live owned
session. Status never reports healthy audit or successful preparation in that
case. Emergency service shutdown still terminates the child when storage fails;
cleanup cannot depend on a healthy log. That cleanup result can only remain in
memory if the journal is unavailable.

The [segmented journal](OPENVPN_JOURNAL_RETENTION.md) retains up to 64 protected
files, each capped at 20,000 records and 16 MiB, with a 4 KiB record-body limit.
A file rollover continues the same chain and revision. New intents reserve their
own space plus eight maximum-size emergency records across remaining capacity.
Actual disk/sync failures still invoke the same audit-fault handling. A torn tail,
invalid chain or missing intermediate segment disables startup of this domain.
There is no truncation, journal reset, PID reattachment or automatic old-intent
retry. `ssk --json winhost vpn journal-inspect` verifies the complete retained
history and capacity offline, with the service stopped. New storage records use
schema 2 to fence readers that do not understand segments; schema-1 history remains
readable. See the linked contract for migration and retention limits.

On restart, clean terminal records permit an idle worker. A pending, held or
unconfirmed previous operation becomes `recovery_required`. An explicitly granted
`recover` command can reconcile a recorded process identity, prove the old process
has ended, remove exactly its private run files, and durably record the result.
The production backend creates the child suspended in its atomic kill-on-close
job and synchronizes PID, Windows creation time and random launch-file ID before
resuming execution. Recovery opens only a read/query handle; it cannot kill or
reattach a recorded PID. Missing identity, a still-live process, unavailable OS
proof, unsafe files or failed audit keep the operation blocked. No override,
journal deletion or automatic repair is provided. Details and the early-crash
limitation are in [the recovery contract](OPENVPN_RECOVERY.md).

Service stop first rejects new work and signals cancellation, then joins the
worker. Active sessions are aborted with OS exit confirmation; pending preparation
checks cancellation before process creation and in accept/authentication loops.
No prepared session survives by design. An unconfirmed exit, unresolved recovery
or unhealthy journal makes the service report a nonzero service-specific stop
code. Worker panics become visible recovery faults; process handles still have
their kill-on-close containment. Synchronous filesystem/OS calls retain their OS
latency; this is not a hard real-time shutdown guarantee.

## Verification and remaining gates

Portable tests exercise authorization, replay/idempotency isolation, concurrency,
durable ordering, journal failures, restart crash points, cancellation, worker
panics, protocol strictness and legacy-version refusal. Windows tests run an actual
contained fixture process through the broker worker and durable file journal,
confirm stop/startup cancellation, secret cleanup and journal file locks, and
exercise real named-pipe authentication/version dispatch beside legacy commands.
The fixture is harmless and **is not OpenVPN**. Temporary-file ACL observations
are injected only through private test seams; the production entry points use
real probes. Same-user pipe tests do not prove the LocalSystem/cross-user boundary.

[Offline pinned-package deployment](OPENVPN_PACKAGE_DEPLOYMENT.md) now stages and
selects bundles with durable deployment intent/result. A pending selection blocks
VPN service startup before Boot/worker creation until explicit offline reconciliation.
It cannot clear unresolved process history or grant tunnel permission.

Still outstanding: approved-distribution/driver compatibility, full product/driver
installation and credential lifecycle, [LocalSystem/SCM and separate-principal VM acceptance](OPENVPN_VM_ACCEPTANCE.md),
legacy/missing-evidence incident handling, external archival/pruning and restore,
verified interface binding, route/DNS enforcement,
kill-switch coupling, tunnel release and IPv4/IPv6 leak/crash/network-change tests.
No actual VPN, service registration, routes or firewall rules were changed on the
development workstation. The daemon's workspace dependency closure remains 17.

Local validation logs for the initial broker increment: `target/restart-audit/vpn-broker-*.log`.
Recovery validation and its additional tests are recorded in [OPENVPN_RECOVERY.md](OPENVPN_RECOVERY.md).

Initial broker increment validation (before recovery): **1,247 workspace tests passed, 0 failed, 1 existing ignored generator**
(including doc-tests), with 26 new tests. Windows workspace/all-targets build and
Clippy (`-D warnings`) pass; Linux all-targets Clippy for the broker, host and CLI
passes. Formatting/diff checks pass. CLI-only tests are rerun after the final
status-output adjustment; Linux was compiled, not executed.
