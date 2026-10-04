# Offline OpenVPN package deployment — 2026-09-22

The Windows CLI can now provision the protected VPN store, stage an independently
approved flat bundle, select it for future held starts, inspect the selection and
reconcile an interrupted selection. This is the **bundle deployment layer**, not
a complete product/driver installer or a production-readiness claim.

No command downloads or executes a package, changes SCM, installs a driver,
releases management HOLD, or changes routes, DNS or firewall policy. VPN routes
continue to report `OPENVPN_NOT_READY`. All public deployment entry points require
the real elevated Windows token and real protected-store ACL checks. There is no
public test/security bypass, `--force`, automatic approval or remote deployment API.

## Operator workflow

Use an elevated offline session after a clean service shutdown. Unresolved process
history must first be resolved using the existing granted recovery workflow; an
update cannot clear it. CLI and service binaries must be upgraded together.

1. Obtain an approved manifest and bundle through the organization's release
   process. Independently obtain the SHA-256 of the **exact manifest bytes** from
   that approval process. Computing a hash from an untrusted download does not
   establish trust. Publisher/signature/revocation verification is not implemented.
2. Run `ssk --json winhost vpn package-provision` for explicit create-or-verify
   provisioning of the fixed store and its initial journal. Existing unsafe
   directories are refused. Startup itself does not provision or repair them.
3. Stage the manifest using its approved hash:

   ```powershell
   ssk --json winhost vpn package-stage C:\Approved\openvpn.json --approved-sha256 <approved-source-manifest-sha256>
   ```

4. Run `ssk --json winhost vpn package-inspect`. It verifies the selected bundle
   and reports its manifest SHA-256, or `selection: null` when nothing is selected.
   Inspect the reported pending transaction before continuing.
5. Select the staged package with an explicit comparison against current state:

   ```powershell
   ssk --json winhost vpn package-activate <package-id> --expected-active none
   # For an update, replace 'none' with the current manifest SHA-256 from inspection.
   ```

`package-stage` returns a package ID equal to the approved **source** manifest
hash. Its `selection` field describes the staged candidate, not the active version;
staging does not change the active selector. The candidate manifest hash differs
from the package ID because staging rewrites `directory` to the protected target.
`package-inspect` and `package-activate` report the actual active selection.
All hashes/IDs use exactly 64 lowercase hexadecimal digits.

An already-selected candidate is a no-op only when `--expected-active` still
matches. An uncertain retry must inspect/reconcile first; a stale expected hash
is refused. To roll back to a previously staged, intact package, explicitly select
its package ID with the current active manifest hash. A pre-existing external
installation is preserved and backed up, but is not automatically turned into a
staged rollback package. Prepare a staged rollback version before migrating it.

The approved source manifest uses the existing strict format:

```json
{
  "schema": 1,
  "protocol": "openvpn-2.6",
  "directory": "C:\\Approved\\bundle",
  "files": [
    {"name": "openvpn.exe", "sha256": "<64 lowercase hex digits>"},
    {"name": "provider.dll", "sha256": "<64 lowercase hex digits>"}
  ]
}
```

The example hashes are placeholders. Declare exactly the actual executable and
every DLL; do not copy this example as an approved release manifest. Protocol 2.6
is the existing management contract, not a recommendation of a specific patch.
Sources must use absolute local paths, with no UNC/device/stream/normalization
ambiguity or reparse ancestors. The source directory can be user-owned because
the manifest and every copied byte are independently hash-pinned. Its files are
opened without write/delete sharing and kept locked through copying. Copying uses
those verified handles, never a second source-path lookup.

## Protected storage and serialization

Under the fixed `%ProgramData%\ScorpioSync\state\openvpn-profiles` directory:

| Artifact | Purpose |
|---|---|
| `package-<package-id>\` | One newly claimed flat bundle directory |
| `package-<package-id>.json` | Completed staged manifest, written only after destination verification |
| `openvpn-installation.json` | Selector already used by the held-launch backend |
| `manifest-<sha256>.json` | Preserved selector/candidate bytes for investigation |
| `installation-<operation-id>.pending.json` | Synced temporary selector; may remain after failure |
| Existing VPN journal files | Durable selection intent/result and service history |

Source and receipt manifests are bounded at 16 KiB. The existing installation
validator requires a complete flat inventory of at most 32 nonempty files, at
most 64 MiB each and 256 MiB total. Every file is hashed, including DLLs. Destination
ACLs/ownership are checked before bytes are written. Files must be regular,
single-link and protected; all relevant directories must be safe and non-reparse.
Staged bytes are synced and then revalidated using the launch-time validator.

All operations hold the same original-journal writer-exclusion lock used by the
service, replay the complete retained history and retain that lock until completion.
Provisioning may create the missing journal; other commands only open an existing
journal. Stage/select additionally require clean terminal history with healthy
audit, no unconfirmed exit and no pending deployment. Another service/deployment
owner, corrupt history or unsafe storage causes refusal.

Partial stage directories and receipt collisions are not overwritten or adopted.
There is no cleanup/pruning implementation: preserve failed artifacts and review
them under an incident procedure. Prior packages and manifest backups remain
untouched. Disk exhaustion remains possible; the protected-store scan is also
bounded at 4,096 entries. Long-term package retention/garbage collection is a
remaining operating requirement, not permission to delete journal evidence.

## Selection transaction and recovery

Selection verifies and pins both candidate and previous bundles, compares the
current selector digest, preserves manifests, and writes a fresh protected,
synced temporary selector. It then durably records `Deployment/Begin` with the
OS-authenticated operator SID, random operation ID and previous/candidate digests.
Only after this intent succeeds may the selector be replaced.

The selector move is within one directory, using Windows `MoveFileExW` with
`MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH`, without cross-volume copying
or delayed reboot operations. The selected file and bundle are read back and
verified before a durable `Deployment/Committed` result. This is **not a claim of
whole-transaction atomicity under power loss**; synchronization, filesystem and
VM failure behavior still require acceptance. API semantics:
[Microsoft MoveFileExW reference](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexw).

If failure occurs before a move, the previous selector remains. Once a move has
been attempted, an error can have an uncertain outcome. A missing completion
record remains pending. The VPN service refuses startup before its Boot record
or worker creation while such an intent exists. It does not automatically select,
undo, start a process or clear the intent.

With the service stopped, run:

```powershell
ssk --json winhost vpn journal-inspect
ssk --json winhost vpn package-reconcile
```

Reconciliation records `Committed` only if the active selector matches the
candidate digest and the selected bundle still verifies. It records `Unchanged`
only if the previous selector/bundle verifies, or if the selector is still absent
and the previous selection was absent. Any other selector, damaged bundle, unsafe
permissions or failed audit leaves the transaction unresolved. Reconciliation
changes only the journal; it never replaces a selector or deletes files.
If package inspection fails, journal inspection can still report the pending
digests when the journal itself is healthy. There is no bypass for torn/corrupt
journal records or lost evidence.

Deployment events preserve all process-status fields except the monotonic
revision. They cannot manufacture an idle state or interleave with process
operations. Old events omit the optional deployment field, preserving their
canonical bytes and hashes. New deployment events require a reader that understands
this event kind; older binaries refuse rather than silently ignore it. Storage
schema remains 2 and VPN pipe protocol remains 3. Binary downgrade is not supported.

## Validation and remaining release gates

Local Windows fixtures exercise actual file locks, copying, hardlink refusal and
selector moves in temporary directories, with private injected ACL observations.
Tests cover initial selection, update/explicit rollback, stale comparisons, wrong
approval/content, incomplete stages, unsafe inherited ACLs, running-owner/dirty
history refusal, pre/post-move interruption, unknown selectors, damaged bundles,
first-install absence and intent/result write failures. Portable tests prove the
pending service-start gate, strict completion matching and unchanged process
status. They do not install or execute OpenVPN.

The subsequent [configuration deployment layer](OPENVPN_CONFIGURATION_DEPLOYMENT.md)
installs protected profiles and per-SID grants together, using the same journal
with a separate transaction target. A pending configuration selection also blocks
package changes; use the matching reconciliation command.

Real inherited ACLs and elevation, LocalSystem/SCM compatibility, publisher trust,
distribution/driver deployment, package/secret retention and failure handling,
power-loss behavior and full VM acceptance remain release gates. Full product/driver
installation and credential lifecycle management are still open. Tunnel/network enforcement is a
separate unfinished requirement. See the [VM matrix](OPENVPN_VM_ACCEPTANCE.md)
and latest [restart assessment](RESTART_ASSESSMENT_2026-09-21.md).
Local evidence: `target/restart-audit/vpn-deployment-*.log`.
