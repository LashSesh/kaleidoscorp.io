# OpenVPN configuration diagnosis and exact restoration — 2026-09-22

The elevated offline CLI can diagnose a missing or damaged managed configuration
and restore the exact bytes last committed in the verified journal. It preserves
the original bytes as confidential evidence and retains unresolved process state.
No command starts a service, runs OpenVPN, releases HOLD or changes network rules.

This workflow requires a previously committed managed configuration. An intentional
change to credentials or grants, including selection of an older version, uses
[configuration deployment](OPENVPN_CONFIGURATION_DEPLOYMENT.md). Restoration can
never select a different digest or revive grants from an earlier snapshot.

## Diagnose before changing files

Stop the service using its normal lifecycle and open an elevated Windows session:

```powershell
ssk --json winhost vpn config-diagnose
```

The command takes the existing journal's writer-exclusion lock, verifies the
retained history and inspects the active document and retained committed copy.
It creates no journal, appends no event and changes no file. The report contains:

- The last committed configuration SHA-256 and complete journal inspection.
- Active/retained artifact state: `missing`, `valid`, `invalid_document`, `unsafe`,
  `too_large` or `unreadable`; hashes are returned only for securely readable,
  bounded files. `valid` describes parsing, not agreement with the committed hash.
- `matches_committed`, pending selection/repair metadata, a suggested `next_step`
  and whether recorded process state requires separate recovery.

Reports omit document bytes, endpoints, certificates and private/TLS keys. A
corrupt journal or unsafe store can prevent diagnosis entirely; the command does
not bypass those checks to produce a success report. `configuration_intact`
describes the file, not overall audit health or VPN readiness.

## Restore the committed bytes

Use the committed digest and active observation returned by diagnosis. For an
absent active file, the observation is the literal `missing`:

```powershell
ssk --json winhost vpn config-restore --expected-committed <committed-sha256> --expected-observed missing
```

For a securely readable damaged or different active file, supply its observed hash
instead. The default source is `configuration-<committed-sha256>.json` in the
protected machine profile store. If that retained copy is unavailable, an already
confidential, independently retained copy can be supplied:

```powershell
ssk --json winhost vpn config-restore --expected-committed <committed-sha256> --expected-observed <observed-sha256> --source C:\ApprovedPrivate\backup.json
```

Both expectations must still match under the journal lock. A stale committed or
observed hash fails before writing evidence or intent. A matching intact active
document is an `already-intact` no-op when no maintenance is pending and audit is
healthy; it needs neither a source copy nor capacity for a new intent.

An [encrypted archive](OPENVPN_CONFIGURATION_BACKUP.md) can instead be supplied
with `--backup <archive> --key-file <separate-key-file>`. These options require
each other and conflict with `--source`. Authentication/decryption happens in
memory and feeds this same transaction without a separate plaintext import file.
Use `config-backup-verify` to check an archive independently, including when the
active file is already intact and restoration would be a no-op.

The source must have the exact committed SHA-256, parse as a complete configuration
and satisfy the existing 1 MiB/profile/policy limits. Absolute local source paths,
administrative ownership, confidential ACLs, regular files, no hardlinks and no
reparse ancestors are required. Source bytes are read through a handle denying
write/delete sharing. The source is never changed, re-ACL'd or copied into the
retained-version namespace. An older valid backup with a different hash is refused.

The active file must be absent or securely readable within the same size bound.
Unsafe permissions, hardlinks/reparse points, oversized or unreadable active files
remain blocked for investigation. There is no `--force`, permission repair or
destructive fallback. Any pending package/configuration selection or restoration
must be resolved using its corresponding reconciliation command first. In
particular, this workflow cannot bypass an already unresolvable selection intent.

## Evidence and transaction order

All artifacts live beneath
`%ProgramData%\ScorpioSync\state\openvpn-profiles`.

1. Verify the journal, expectations and exact source. Reserve journal capacity.
2. If active bytes exist, claim `configuration-evidence-<operation-id>.json`,
   check its inherited confidential ACL before writing, synchronize, then read
   back and verify the original digest. Keep the evidence handle locked.
3. Claim and synchronize `configuration-restore-<operation-id>.pending.json`
   containing the validated source, using the same confidentiality checks.
4. Synchronize `Deployment/RestoreBegin` with operator SID, operation ID, committed
   digest and observed digest/absence. Only then replace the active file through
   the existing same-directory Windows selector move.
5. Read back the active file, verify its committed hash and full document, then
   synchronize `RestoreCompleted`. Return the resulting diagnosis.

Only the active document is repaired. The journal's committed configuration digest
never changes. Every process-status field, including PID, creation time, launch ID,
exit confirmation and recovery phase, is preserved; only the status revision
advances for audit records. Therefore exact restoration is allowed with unresolved
process history and healthy audit. A subsequent service start must still enforce
the usual [explicit process recovery](OPENVPN_RECOVERY.md), its grants and OS proof.

Evidence, retained sources and interrupted temporary files can contain private
keys in plaintext protected by ACLs. They are not encrypted archives. No automatic
export, upload, cleanup or deletion is provided. An artifact created before a
failed intent can remain without a journal reference; retain it for investigation.

## Interrupted restoration

Inspect, preserve the artifacts and explicitly reconcile:

```powershell
ssk --json winhost vpn config-diagnose
ssk --json winhost vpn config-restore-reconcile
```

Reconciliation verifies the preserved evidence whenever the original file existed.
It then records only an observed outcome, without moving/deleting configuration
files. Missing or changed evidence cannot be dismissed even when the active file
already matches the committed digest.

| Interruption or observation | Result |
|---|---|
| Before durable intent | Active file is unchanged; partial evidence/temporary files may remain |
| Intent exists; active still equals the original observation, including absence | Record `RestoreUnchanged`; the configuration may still need repair |
| Intent exists; active matches the committed hash and parses fully | Record `RestoreCompleted` |
| Active is neither the original observation nor the committed document | Refuse completion and preserve pending state |
| Evidence is missing, altered, unsafe or unreadable | Refuse completion and preserve pending state |
| Result append/sync fails | No success claim; replay determines durable state; pending repair blocks startup |
| Journal is torn/corrupt, audit unhealthy or required capacity unavailable | Refuse; no reset, truncation or replacement history |

A pending repair blocks VPN-domain startup and other package/configuration
maintenance. `config-reconcile` and `package-reconcile` cannot complete it.
After `unchanged`, diagnose again before explicitly retrying restoration. Repeated
reconciliation without a pending repair is an error, not a new repair operation.

## Compatibility and validation limits

The new `RestoreBegin`, `RestoreCompleted` and `RestoreUnchanged` deployment variants
preserve existing canonical record bytes and hashes. Readers predating these
variants refuse them; binary downgrade after restoration is unsupported. Journal
schema remains 2, VPN wire protocol 3 and the independent boundary protocol 1.
Inspection now includes `pending_repair` in addition to `pending_deployment`.

Local tests cover read-only/redacted diagnosis, exact-version binding, stale
expectations, protected evidence, missing files, alternate source copies,
ACL/hardlink/size refusal, unchanged unresolved process identities, interruption
on both sides of the move, audit failures and evidence loss/tampering. They use
temporary Windows files and private injected permission observations. They do not
prove real LocalSystem ACL behavior or whole-transaction power-loss durability.

This is configuration-file restoration from existing verified bytes. Encrypted
configuration backup creation is now available in the linked workflow; journal archive restoration/external anchoring, whole-machine
disaster recovery, secret retention/cleanup, missing-evidence incident procedures
and tunnel enforcement remain open. The [VM matrix](OPENVPN_VM_ACCEPTANCE.md)
contains unexecuted restoration checks. Results are recorded in the latest
[restart assessment](RESTART_ASSESSMENT_2026-09-21.md).
Local evidence: `target/restart-audit/vpn-restore-*.log`.
