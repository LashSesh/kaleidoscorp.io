# Protected OpenVPN journal snapshots and quarantined recovery — 2026-09-22

The offline CLI can now copy all verified journal segments into one new archive
and verify that archive against independently retained expectations. It preserves
the original segment bytes, boundaries, record chain, revision, committed
configuration digest and pending process/deployment/repair state. The live journal
is not modified. A subsequent quarantine workflow can now reconstruct exact
journal files and preserve damaged originals while fencing service startup.
**Activation of reconstructed history, external anchoring services and complete
disaster recovery remain open**.

## Capture a stopped, consistent journal

Use an elevated Windows session. Stop the service using the reviewed service
procedure and confirm that it is stopped. The command does not stop/start it.
Provision a confidential administrative archive parent separately, outside the
live profile store. The tool refuses unsafe/missing parents, reparse paths and
hardlinked files; it never repairs ACLs or overwrites an existing output.

```powershell
ssk --json winhost vpn journal-inspect
ssk --json winhost vpn journal-backup C:\PrivateBackups\journal-2026-09-22.sskj --expected-head <retained-head> --expected-records <retained-count>
```

Both expectations are mandatory. `head` is the journal's lowercase 64-digit
**BLAKE3** chain digest, not a file SHA-256. `records` is the number of verified
events. For an empty origin, the count is zero and the head is 64 zeroes. Empty
history is preserved as empty; it does not authorize deployment or recovery.

Review and retain the inspection separately. If an earlier independently trusted
checkpoint exists, an unexpected regression must be investigated; do not replace
it with a newly inspected shorter history merely to make a comparison pass.
Backup takes the same writer-exclusion locks as the service and verifies the
complete existing chain before claiming an output. A changed expected head/count
fails before any archive file is created. Locks cover every source segment for
the whole copy and readback. No missing live journal is created.

The output is opened exclusively with `create_new`. Its inherited confidentiality
is checked before the first byte is written. Data is copied through bounded
buffers, synchronized, read back for exact SHA-256 comparison, then replayed with
the production journal decoder and transition checks. Existing/partial outputs
are preserved on failure; investigate and choose a new path for a retry. A
complete but unacknowledged output can be verified against expectations already
held independently. There is no overwrite/resume/delete switch.

No journal event is appended for the export itself: the snapshot's head must stay
stable. Retain the command result and operator/change record separately. Automated
export auditing, inventory monitoring and retention enforcement are not implemented.

## Independently retain the result and verify the archive

The successful report supplies archive SHA-256, archive byte length and the full
historical inspection. Preserve the following in separately controlled custody:

| Value | Purpose |
|---|---|
| Machine/service identity and environment | Associate this history with the intended installation; not inferred or attested by the archive |
| Capture time, operator/change record and source build | Establish provenance and explain when/why the snapshot was made |
| Archive SHA-256 and size | Identify the exact envelope and segment bytes |
| Journal head and record count | Detect changed or removed history against the retained expectation |
| Last status, configuration digest, pending deployment/repair | Preserve unresolved work and correlate separately retained configuration/package assets |
| Custodian and approved transfer/storage location | Keep the reference independent of a replaceable archive |

At the destination, use a trusted build, elevated access and an existing
confidential archive directory. The verifier has no dependency on the current
machine profile store and can run when that store is missing or damaged:

```powershell
ssk --json winhost vpn journal-backup-verify C:\PrivateBackups\journal-2026-09-22.sskj --expected-archive-sha256 <independently-retained-sha256> --expected-head <independently-retained-head> --expected-records <independently-retained-count>
```

All three expectations are required. The file stays open without write/delete
sharing while its size, SHA-256, framing and full journal semantics are checked.
The verifier writes no files and prints no success report on failure. CLI failures
use `VPN_JOURNAL_ARCHIVE_FAILED`. A changed, truncated, reordered or extended
archive fails. An internally valid history with a removed complete tail still
fails against the independently retained later head/count, even if its archive
SHA-256 was recomputed.

The caller is responsible for the provenance and freshness of these expectations.
If an attacker can replace both the archive and its supposedly trusted reference,
this mechanism cannot distinguish the replacement. No signature, remote witness,
monotonic hardware counter or machine identity attestation is provided. A valid
old archive is not proof of the latest machine state. Service startup does not
automatically consult these external expectations.

`inspection.last_status` remains historical. Pending operations and unconfirmed
process exit are preserved, never cleared. Archive inspections always report
`accepts_intent: false` and zero writable slots because archives are read-only.
`restoration_performed` always remains false. A verified backup never permits
automatic tunnel startup, a rights rollback or killing a PID from an old snapshot.

## Format, confidentiality and limits

The version-1 envelope is `SSKJNL01` (8 bytes), a little-endian u32 segment count,
then for each segment a little-endian u64 byte length followed by its exact
original bytes. Index zero denotes `openvpn-control.journal`; subsequent indices
denote their canonical six-digit segment names. There are no stored paths,
arbitrary extra files or caller-selected extraction paths. The quarantine workflow
below reconstructs only canonical names in fixed protected directories. Trailing bytes are rejected.

Production limits remain 64 segments, 16 MiB and 20,000 records per segment, and
4 KiB per record body: at most 1 GiB of journal bytes plus 524 envelope bytes.
Only a final segment may be empty; multiple segments require the existing schema-2
fence in the origin. Single legacy schema-1 histories remain readable unchanged.
Frame replay holds one bounded record; copying/hashing uses 64 KiB buffers.
Verification performs full sequential passes, so full-capacity latency and
power-loss durability still need VM measurement.

This archive contains **unencrypted confidential journal metadata**, including
principal/profile identifiers and historical process state. It contains no
configuration file, private key, management secret, run file, driver or executable.
Windows ACLs protect the source and destination; the format does not provide
encryption at rest or in transit. Use separately approved encrypted storage and
transfer where needed. Do not treat it like the encrypted configuration backup or
put it in the public development kit or sanitized acceptance evidence files.

## Reconstruct in blocked quarantine

The new commands reconstruct a verified archive in the existing protected machine
profile store. They **persistently block normal journal startup** and never activate
the reconstructed journal. Run them only as part of an explicitly reviewed recovery
exercise on a disposable VM or a controlled incident. No release/removal command
for this fence is available in this increment. They are not a backup rehearsal
to run casually against an otherwise operating installation.

First stop the service through the existing service procedure. In an elevated
Windows session, fingerprint the original set without parsing damaged record bodies:

```powershell
ssk --json winhost vpn journal-diagnose
```

The result lists canonical segment indices, sizes and SHA-256 values and a single
`observed_sha256` binding the sorted metadata set. Gaps, a missing origin and an
empty set are represented without creating replacement files. Noncanonical journal
names, unsafe ACLs/hardlinks/reparse points, inaccessible or oversized files cause
refusal. Diagnosis does not clear damage or declare the history healthy. If a
recovery marker exists, diagnosis additionally reports its exact
`recovery_plan_sha256`; an unreadable/oversized marker causes refusal.

Verify archive/head/count against the separately controlled incident reference
and retain the observed-set digest. Then begin reconstruction:

```powershell
ssk --json winhost vpn journal-recovery-stage C:\PrivateBackups\journal-2026-09-22.sskj --expected-archive-sha256 <trusted-sha256> --expected-head <trusted-head> --expected-records <trusted-count> --expected-observed <diagnosed-original-set-sha256>
```

The archive is fully verified and pinned with a read handle. The original segment
set is locked and compared with the diagnosis before any marker is claimed.
Empty archived history cannot be used as a recovery candidate. The tool creates
and synchronizes a confidential, immutable recovery plan at the fixed path:

```text
openvpn-profiles/
  openvpn-control-recovery.journal     # permanent startup fence and pinned plan
  openvpn-control*.journal             # original files remain in place
  journal-recovery-<random-id>/
    attempt-0001/
      evidence/openvpn-control*.journal  # exact copies of observed original files
      candidate/openvpn-control*.journal # exact reconstructed archive segments
      complete.json                      # completion bound to the recovery plan
```

The marker name belongs to the reserved journal namespace. Its mere presence
blocks current and older **segmented** readers before they can create a missing
origin. Empty/torn marker contents also block startup. Readers older than the
segmented format remain unsupported; do not downgrade binaries during recovery.
The marker is exclusively locked during stage/resume, preventing another recovery
writer. Source locks and inventory rechecks also prevent a successful report for
a source set changed during capture. No service is stopped/started automatically.

The reconstructed files and original evidence are written through fixed names
with `create_new`, checked for confidential inheritance before bytes, synchronized,
hashed and replayed. The candidate must reproduce the exact archive SHA-256,
including segment boundaries, as well as its expected head/count. Evidence must
match the original-set digest. Files remain pinned while the completion receipt
is written, synchronized and read back. Only then is a successful report emitted.
Unconfirmed process exit and pending configuration/deployment/repair state remain
historical facts; no PID is killed and no rights are recreated from those facts.
Treat damaged original bytes and their evidence copies as opaque confidential
data; diagnosis reports hashes and sizes, never those contents.

Retain `plan_sha256` with the incident reference. After a crash or uncertain result,
diagnose the store and compare the plan and original-set values to that reference.
Then resume using the same archive expectations and the independently pinned plan:

```powershell
ssk --json winhost vpn journal-recovery-resume C:\PrivateBackups\journal-2026-09-22.sskj --expected-archive-sha256 <trusted-sha256> --expected-head <trusted-head> --expected-records <trusted-count> --expected-observed <original-set-sha256> --expected-plan-sha256 <pinned-plan-sha256>
```

If the first call failed before returning its plan hash, a freshly diagnosed hash
is not automatically a trusted reference: review the retained plan against the
already approved archive/head/count and original-set evidence before pinning it.
An unreadable or malformed plan stays blocked; there is no reset or truncation.

A complete attempt is fully reverified and returned unchanged. An incomplete
attempt stays untouched and the next attempt receives a fresh directory; even
torn copy files are preserved. At most four attempts are allowed. With the journal
limits, copies can consume up to 8 GiB plus small metadata across those attempts,
in addition to the original store and source archive. I/O failures keep the fence.
Changed completed evidence, altered receipts, unexpected attempt ordering, changed
originals or mismatched references cause refusal. There is no silent overwrite,
automatic cleanup, retention extension, `--force` or `--activate` option.

Successful reports always contain `service_blocked: true` and
`activation_performed: false`. Keep the marker, all attempts and all originals.
Here `service_blocked` refers to initialization of the VPN domain and its journal;
the SCM service may still run diagnostics and other independent control domains.
**Do not delete the marker to resume service:** that would bypass the recovery
interlock and fall back to the original history. Admission of reconstructed state
requires a future reviewed transaction and explicit checks below.

## Remaining recovery boundary

Do not manually replace live segments from this archive. A safe restore still
needs independently established latest machine state and a recoverable activation
transaction. Preservation of damaged originals, a service-start interlock and
resumable reconstruction now exist in quarantine; live replacement remains unsupported.
Old process identities require fresh OS proof; configuration/package selectors
must be reconciled with the preserved commitments. Missing evidence stays blocked.
No journal-reset or history-pruning procedure is authorized by backup verification.

J07 and B06 remain blocked until those activation and operational prerequisites
are implemented and actually exercised. Local tests use real temporary files,
Windows sharing/hardlink behavior and private synthetic ACL observations; they
do not establish real cross-user ACLs, VM acceptance or power-loss recovery.

See [retention](OPENVPN_JOURNAL_RETENTION.md), [configuration backups](OPENVPN_CONFIGURATION_BACKUP.md),
[VM acceptance](OPENVPN_VM_ACCEPTANCE.md) and [current assessment](RESTART_ASSESSMENT_2026-09-21.md).
