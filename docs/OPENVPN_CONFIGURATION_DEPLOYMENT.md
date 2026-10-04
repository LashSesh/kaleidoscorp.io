# OpenVPN profiles and grants as one configuration — 2026-09-22

The Windows service now uses a fixed configuration snapshot containing both VPN
profiles and their per-SID grants. Elevated offline CLI commands stage, select,
inspect and reconcile that snapshot. Updating credentials and authorization is
one selection, with no intermediate combination of new grants and old profiles.
No command starts OpenVPN, controls SCM, releases HOLD or authorizes tunnel traffic.

## Document and approval contract

The source is a confidential JSON document containing exactly `schema`, `policy`
and `profiles`. `schema` is 1. `policy` is the existing strict schema-1 policy
object; `profiles` is an array of complete [profile-v1 objects](OPENVPN_PROFILES_AND_PROCESS.md).
They are nested objects, not filenames, JSON strings or raw `.ovpn` directives.
This complete document is a valid **revoke-all** configuration:

```json
{
  "schema": 1,
  "policy": {"schema": 1, "grants": []},
  "profiles": []
}
```

To grant access, add the actual complete profile and an entry such as
`{"sid":"S-1-5-21-1-2-3-1001","profile":"company-managed","verbs":["status","prepare","stop","recover"]}`
to `policy.grants`, replacing the illustrative SID with the intended principal.
Every granted profile must exist in the same document. There is no wildcard,
administrator override, inherited boundary permission or implicit status/recovery
grant. Omitting a prior grant revokes it when the service starts with the new
snapshot. Profiles without grants are allowed; duplicate profile IDs are refused.

Bounds: 1 MiB for the exact whole document, at most 32 profiles, the existing
128 KiB per-profile bound, and the existing 32 KiB/128-entry policy bound. Unknown
and duplicate fields, trailing documents, unknown versions and invalid nested
profile/policy fields are refused. Nested raw JSON is borrowed and passed to the
original strict parsers; it is not normalized through a generic JSON value that
could silently discard duplicate fields. Profile validation still does not prove
certificate validity, key strength or a working VPN connection.

Obtain the exact document SHA-256 independently from the organization's approval
process. `--approved-sha256` binds the supplied bytes to that expected value; it
does not authenticate an approver, enforce dual control or verify a signature.
The document contains private keys. Source files must already have an administrative
owner and confidential ACL, with no non-administrative allow entries, even read
or inherit-only ones. Absolute local paths are required; reparse ancestors,
device/UNC paths, ambiguous path forms and hardlinked files are refused. Staging
never changes source ACLs or tries to repair an unsafe source.

## Offline operator workflow

Complete any outstanding process recovery and stop the service cleanly. Use an
elevated Windows session. The existing `package-provision` command provisions the
fixed protected VPN store and initial journal if needed; the configuration commands
require that journal to exist and use its lifetime writer-exclusion lock.

```powershell
ssk --json winhost vpn config-stage C:\ApprovedPrivate\vpn.json --approved-sha256 <approved-document-sha256>
ssk --json winhost vpn config-inspect
ssk --json winhost vpn config-activate <approved-document-sha256> --expected-active none
```

For subsequent updates, replace `none` with the current configuration hash from
inspection. `none` means that no **managed** snapshot has been selected yet; a
legacy control policy may still exist. No CLI command stops/restarts the service
automatically. The normal service lifecycle must be completed separately.

Staging validates everything before claiming `configuration-<sha256>.json` in
`%ProgramData%\ScorpioSync\state\openvpn-profiles`. The inherited destination
ACL is checked before writing any secret bytes, the file is synced and read back,
and its hash/contents are checked again. Existing filenames, including incomplete
stages, are never overwritten or adopted. The stage report describes the candidate;
it does not indicate an active selection.

Selection compares both the active file and the last committed journal digest to
the expected predecessor. It selects the complete document as
`openvpn-configuration.json`. Staged versions remain available. A rollback is an
explicit selection of a previous intact staged hash with the current expected
hash; it restores that version's **credentials and grants together**, including
any rights revoked since then. It must receive the corresponding operator review.
Selecting the already-current hash with the correct expectation is a no-op.

An empty managed snapshot is the supported way to revoke all VPN grants. Removing
the active file is not a disable/uninstall operation and cannot revive legacy
permissions after a managed configuration was committed.

## Transaction and service startup

The shared journal serializes configuration changes, package changes and process
operations. Stage/select require clean terminal process history, healthy audit
and no pending deployment or configuration repair. Selection additionally checks capacity for its intent
and completion. Staging writes no intent because it does not select permissions.
Selection writes and syncs a fresh
confidential `configuration-change-<operation-id>.pending.json`, then durably
records `Deployment/Begin` with target `Configuration`, operator SID, operation ID,
and previous/candidate digests. No credential bytes enter those journal events.

Only after that intent succeeds is the active file replaced using the same
same-directory Windows move as [package selection](OPENVPN_PACKAGE_DEPLOYMENT.md).
Readback must match the candidate and parse fully before `Committed` is synced.
The journal remembers the committed configuration digest across restarts.
This is not a whole-transaction power-loss guarantee; real filesystem/VM failure
behavior remains an acceptance requirement.

Service startup now acquires and verifies the journal **before** reading policy
or building the pipe admission list. A pending deployment or repair refuses the VPN domain
before policy exposure/worker creation. Otherwise the active document must match
the committed digest. The service keeps its file handle locked against write/delete
and holds the parsed policy and profiles in memory for the worker's lifetime.
The authorization policy, pipe SID list and launch profile come from that same
snapshot. Profiles are not reopened from unrelated legacy files for each launch.
Changes require a stopped service and take effect on its next start; there is no
hot-reload window or automatic connection attempt. Public unaudited convenience
launch methods have been removed; production preparation is crate-internal and
uses the broker's identity-audit callback.

If selection completion is missing, preserve the artifacts and use:

```powershell
ssk --json winhost vpn journal-inspect
ssk --json winhost vpn config-reconcile
```

Reconciliation accepts only the verified candidate or predecessor (including
absence for a first installation that did not select anything). It records the
observed outcome without replacing/deleting files or starting a process. Unknown
content, unsafe ACLs, malformed documents and journal failure remain blocked.
Package reconciliation cannot complete a configuration transaction, or vice versa.
Do not reset/truncate the journal or delete pending evidence to clear a failure.

When there is no pending selection, a missing or damaged committed active document
can be diagnosed and restored using [exact configuration restoration](OPENVPN_CONFIGURATION_RESTORE.md).
That workflow accepts only the journal's committed digest and preserves the
original bytes and process recovery state. It does not override an unresolved
selection transaction or select an older permission snapshot.

## Migration and compatibility

Before the first managed configuration commit, an absent managed file permits
the legacy `openvpn-control.json` and `vpn-<id>.json` layout. The policy is read
under the journal lock, and up to 32 referenced profiles are loaded into the
in-memory snapshot. Missing/invalid/unsafe individual legacy profiles are excluded
from preparation and logged without credentials. Separately valid status/recovery
grants remain usable, so a missing old profile cannot by itself prevent process
recovery. Repairing such a legacy profile requires a service restart to reload it.
Unsafe storage or policy still refuses the domain. Managed documents always
require complete valid references; this legacy exception does not apply to them.

Once a managed selection is committed, the journal digest permanently disables
implicit legacy fallback. Missing, altered or unjournaled active documents cause
refusal. An earlier staged snapshot can be selected explicitly; returning to the
untracked legacy layout is not supported. Config inspection reports the managed
selection only; `null` is not a claim that no legacy grants exist.

Existing package deployment events omit the new default target field, retaining
their canonical bytes and hashes. Configuration events explicitly name their
target; older readers reject the unknown field. Journal storage schema stays 2,
VPN wire protocol stays 3, and the independent boundary protocol stays 1.
Upgrade service and CLI together; binary downgrade after migration is unsupported.

## Secret handling, validation and remaining gates

Reports contain only action, configuration digest, profile IDs, principal SIDs and
pending transaction metadata. They never print profile endpoints, certificates,
private keys or TLS keys. Input/read buffers use `Zeroizing` with bounded capacity;
parsed profile secret fields retain their existing wipe-on-drop behavior. These
are plaintext files protected by ACLs, not encrypted secrets. There is no claim
that parser/OS internals, paging, crash dumps or backups never contain copies.
Old snapshots and interrupted temporary files also contain secrets. The subsequent
[encrypted backup workflow](OPENVPN_CONFIGURATION_BACKUP.md) protects explicit
archives with separately retained keys and supports exact restoration. Retention,
key custody and approved cleanup remain operating requirements; there is no
garbage collection or automatic deletion of the existing plaintext artifacts.

Tests use real temporary Windows files, handle locks and selector moves, with
private injected ACL observations. They cover approval/content/permission refusal,
complete update/revocation/rollback, secret-free output/audit, interrupted moves,
intent/result failures, legacy recovery, permanent no-fallback behavior, empty
revocation and domain-separated journal completion. Portable tests cover strict
nested parsing, size/reference constraints and old audit-byte compatibility.
No real OpenVPN, SCM service, driver or tunnel is installed or activated.

Real elevated ACL inheritance and separate-user access, LocalSystem/SCM startup,
power loss, approved distribution/driver compatibility, PKI/credential lifecycle,
secret archival/cleanup, missing-evidence incident procedures and tunnel enforcement
remain release gates. See [the unexecuted VM matrix](OPENVPN_VM_ACCEPTANCE.md) and
the latest [restart assessment](RESTART_ASSESSMENT_2026-09-21.md).
Local evidence: `target/restart-audit/vpn-configuration-*.log`.
