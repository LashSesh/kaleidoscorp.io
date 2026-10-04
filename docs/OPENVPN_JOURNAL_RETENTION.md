# OpenVPN journal segmentation and retention — 2026-09-22

The production service now continues a full VPN journal in the next protected
segment. Prior segments remain in place, and one hash chain, record sequence and
status revision span every file. This removes the former single-file exhaustion
point without resetting history, recovery state or authorization. The broker's
intent-before-effect and result synchronization rules still apply.

## Storage layout and limits

All files live in the existing protected machine profile directory:

```text
%ProgramData%\ScorpioSync\state\openvpn-profiles\
  openvpn-control.journal             # segment 0 and permanent writer lock
  openvpn-control-000001.journal
  openvpn-control-000002.journal
  ...
  openvpn-control-000063.journal
```

The limits are fixed in this increment: 64 segments; each has at most 20,000
records and 16 MiB including length headers; each record body is at most 4 KiB.
Both bounds apply, so the total is at most 1,280,000 records and 1 GiB, whichever
limit is reached first for the actual record sizes. No segment is preallocated.
The reserved journal namespace is case-canonical, has six-digit numeric suffixes,
and requires a contiguous sequence starting at segment 0. Directory inspection
is bounded to 4,096 entries, including other profile/control/run files.

The original file retains an open handle denying write/delete sharing throughout
the service lifetime. Every discovered segment is similarly locked and checked
for confidentiality, regular-file type, reparse points and hardlinks. A second
service or offline inspector cannot become another writer. Discovery runs again
after acquiring the original lock, covering a rotation that completed during the
first directory scan. A missing origin or intermediate segment is refused before
claiming any replacement file.

Before an append would exceed the active segment's byte or record bound, the
store claims the next fixed filename with `create_new`. It verifies the inherited
permissions before writing, synchronizes the new file, then appends and synchronizes
the next record. Collisions and unsafe files are refused without overwriting them.
The prior segment is retained byte-for-byte. No caller can supply a path, segment
number, alternative storage directory or retention override through the CLI/IPC.

A new intent needs room for itself **plus eight maximum-size emergency records**.
The check accounts for both bytes and record counts, including remaining segments.
It is a conservative format-capacity calculation, not a guarantee of free disk
space or successful hardware I/O. Capacity pressure returns `AuditUnavailable`
before the intent/effect; an actual append/sync failure invokes the existing
latched audit fault and owned-session cleanup. Emergency shutdown can still run
when the log cannot be written, but its result may then remain only in memory.

## Crash behavior and verification

Replay streams one bounded record at a time, validates schema/hash/sequence/revision
across segment boundaries, and retains only the last status and chain head. It
does not load the entire retained history into a vector. Startup still reads and
verifies the whole history; full-capacity startup/SCM latency needs VM measurement.

| Crash or fault | Behavior |
|---|---|
| Before next segment is claimed | Replay and append continue from the previous file |
| After claim, before the first record | One empty final segment is accepted and receives the next record |
| Partial frame, corrupt record or broken cross-file chain | Domain startup fails; no truncation or repair |
| Missing origin/intermediate file, empty intermediate file or malformed journal name | Refusal; no replacement history |
| Unsafe permissions, hardlink/reparse point or filename collision | Refusal before record bytes are written to that file |
| Rotation while an attempt is unresolved | Original unresolved status survives; recovery remains required |
| Total retention bound reached | Further appends fail; old records remain intact |

These rules address process crashes and ordinary sync failures. Power-loss,
filesystem/device durability and full-capacity SCM timing are unexecuted VM gates,
not claims established by the local fixture suite.

## Format compatibility

The VPN wire protocol stays at version **3**, independently of journal storage.
New journal records use **schema 2**, and include that schema value in their hash.
The new reader accepts both schema 1 and schema 2, preserving old bytes and hashes.
Existing record bytes and hashes remain unchanged. Subsequent
[package deployment](OPENVPN_PACKAGE_DEPLOYMENT.md) adds a `Deployment` kind and
optional metadata; old events omit that field. Readers predating this event kind
refuse new deployment records. Binary downgrade after deployment is unsupported.

Before the first rollover, the original file must contain a successfully written
schema-2 record. A previous service supports only schema 1 and therefore refuses
that original file instead of silently continuing an old history while ignoring
new segment files. A legacy journal with no room for its first schema-2 append
is refused with a migration-required error; this increment does not rewrite it.
Upgrade before exhaustion. Offline inspection can still verify and report such
an old full journal. Binary downgrade and already-exhausted legacy migration need
a reviewed procedure; deleting history is not a supported migration.

## Offline operator inspection

With the service fully stopped, and using an account with access to the protected
store, run:

```powershell
ssk --json winhost vpn journal-inspect
```

The command uses existing fixed files only. It takes the same writer-exclusion
lock as the service but writes no boot/status event, creates no missing journal,
and performs no cleanup. Protected-store write access is needed to acquire that
lock. Running it while the service holds the journal fails. It does not stop or
start the service automatically and does not bypass store ACL checks.

A successful report contains record count, verified head digest, last recorded
status, segment count/limit, active records/bytes, total bytes/limit and conservative
remaining record slots. `accepts_intent` describes storage capacity alone; it is
not an authorization, health or VPN-readiness verdict. `last_status` is historical,
and an unresolved or unhealthy status is not cleared by inspection. Failed
verification returns `VPN_JOURNAL_INSPECTION_FAILED` without a success report.
`pending_deployment` additionally identifies an interrupted deployment selection;
only its corresponding offline reconciliation can complete it, and process startup is blocked
while it remains pending. Inspection never completes such a transaction.
Subsequent [configuration deployment](OPENVPN_CONFIGURATION_DEPLOYMENT.md) uses an
explicit `Configuration` target and its own reconciliation command. The default
omitted target still means package, preserving old hashes. `configuration_digest`
records the last committed managed configuration and prevents legacy fallback
after migration. No secret configuration bytes are stored in the journal.

[Exact configuration restoration](OPENVPN_CONFIGURATION_RESTORE.md) adds
`RestoreBegin`, `RestoreCompleted` and `RestoreUnchanged` deployment variants and
the inspection field `pending_repair`. Pending repairs also block startup and
maintenance, and require `config-restore-reconcile`. They preserve the committed
digest and all process-status fields except revision. Existing event hashes remain
unchanged; older readers reject the new variants. This does not restore or repair
journal archives.

For a retained backup, preserve the original file **and all numbered segments**
as one protected set while the service is stopped. The subsequent
[protected journal snapshot commands](OPENVPN_JOURNAL_BACKUP.md) now export that
complete set and verify archives against independently retained SHA-256, chain
head and record count. Keep the reviewed report and expectations separately.
There is no upload, pruning, deletion or restoration of live archives. Removing
an intermediate segment breaks verification. Removing the entire tail can still
be undetectable without an external trusted anchor, just as truncating an old
single-file history could be. A local hash chain is not administrator-proof or
externally signed evidence.

The subsequent [quarantine recovery workflow](OPENVPN_JOURNAL_BACKUP.md#reconstruct-in-blocked-quarantine)
can diagnose damaged bytes, preserve originals and reconstruct a verified candidate.
Its reserved `openvpn-control-recovery.journal` marker blocks all normal journal
opens, including missing-origin creation, even when the marker is empty or torn.
The candidate is not activated; the marker and every attempt remain retained.

## Remaining operational gates

The local default retains all segments until its fixed bound. Time-based deletion,
external archive transport/anchoring, verified restore, capacity monitoring without stopping
the service, approved pruning and already-full legacy migration remain open.
They need an explicit operating policy and implementation before unattended
production deployment. No automatic deletion policy has been inferred.

Twelve Windows tests cover record/byte rollover, unchanged old bytes, cross-segment
replay, exclusive locks, capacity reservation, empty-final crash recovery, torn
frames, corruption/reordering, missing/noncanonical segments, offline inspection,
legacy fencing, collisions, ACL/hardlink refusal and unresolved-state preservation.
Two portable tests cover streaming replay/schema binding and broker refusal before
effects at capacity. Existing real harmless-child broker/recovery tests now use
the production segmented store through private ACL fixture seams. Real ACL/SCM,
power-loss and full-capacity acceptance remain [planned VM checks](OPENVPN_VM_ACCEPTANCE.md).

Current results are in the latest [restart assessment](RESTART_ASSESSMENT_2026-09-21.md).
Local evidence: `target/restart-audit/vpn-journal-*.log`.
