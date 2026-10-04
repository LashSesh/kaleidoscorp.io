# Recording OpenVPN VM acceptance evidence — 2026-09-22

`ssk-vpn-acceptance` is a separate offline evidence recorder and verifier. It
creates a run bound to VM/build metadata, retains reviewed observations and
sanitized evidence, verifies their hashes and checks coverage across en-US and
de-DE. The [49-case matrix](OPENVPN_VM_ACCEPTANCE.md) remains unexecuted against
a real OpenVPN/LocalSystem deployment. Tool tests use synthetic VM assertions.

The recorder never executes supplied binaries, invokes a shell, installs or
controls services/drivers, changes ACLs/network settings, or performs fault
injection. Tests are executed separately in a disposable VM using the operational
workflows. An operator supplies facts and outcomes; this is not VM detection,
remote attestation, semantic validation of observations or a release authority.

## Build and prepare a run

Without an available VM, prepare the [development transfer kit](OPENVPN_TEST_KIT.md)
using `kit-create` and check its exact contents with `kit-verify`. The included
read-only host probe supports resource planning. None of these commands creates
a VM, initializes a claimed acceptance run or marks any case passed.

Build the CLI, service and recorder from one reviewed source state:

```powershell
cargo build --release --locked -p ssk-cli -p ssk-winhost
```

The binaries are `ssk.exe`, `ssk-svc.exe` and `ssk-vpn-acceptance.exe`. Existing
`cargo run -p ssk-cli -- ...` still selects `ssk` through `default-run`.
Use absolute local paths for every recorder file/directory argument. UNC/device
paths, alternate streams, parent traversal and symlink/reparse paths are refused.

Prepare an existing protected evidence parent outside the source checkout and
outside the product's state store. The recorder does not validate/provision
Windows ACLs; restrict access separately because even sanitized evidence may
contain infrastructure identifiers and principal SIDs. Do not submit raw profiles,
keys, management conversations, packet payloads or secret backup archives.

Copy [the context template](examples/openvpn-acceptance-context.json) to a reviewed
UTF-8 JSON file without a BOM. Replace every example/placeholder with actual facts:

| Field group | Source and meaning |
|---|---|
| `vm_id`, `snapshot_id` | Hypervisor inventory and clean disposable snapshot |
| `windows_build`, `locale` | Exact OS build and confirmed Windows locale; supported runs are en-US and de-DE |
| Three environment booleans | Explicit operator confirmation of a disposable VM, isolated network and test-only credentials |
| Principal SIDs | Actual operator, granted standard user, ungranted standard user and administrator without VPN grants; the three test principals must differ |
| `source_revision`, `worktree_dirty` | Full source revision and accurate local modification state; preserve the source snapshot separately when dirty |
| Distribution/driver fields | Approved distribution name/version, driver version, approved manifest SHA-256 and driver artifact SHA-256 |
| `configuration_sha256` | Initial approved managed configuration for this run; later deliberate changes belong in case evidence |

Useful read-only Windows observations include `Get-CimInstance Win32_OperatingSystem`,
`Get-WinSystemLocale`, `Get-UICulture`, `whoami /user`, and `Get-FileHash -Algorithm
SHA256 <approved-file>`. Record each principal from its own session. These facts
are not gathered or authenticated automatically. False prerequisite booleans,
missing/unknown/duplicate fields, unsupported locales and malformed hashes/SIDs
are refused. Syntactic validation cannot establish that the claimed VM or binary
approval is genuine. Never turn placeholders into claimed evidence.

Provision the VM separately using the reviewed [package](OPENVPN_PACKAGE_DEPLOYMENT.md),
[configuration](OPENVPN_CONFIGURATION_DEPLOYMENT.md) and service/driver procedures.
Missing deployment prerequisites leave affected tests blocked. Confirm console
access and snapshot recovery before any failure injection.

Initialize a new run directory, which must not already exist:

```powershell
$Acceptance = 'C:\ReviewedBuild\ssk-vpn-acceptance.exe'
& $Acceptance matrix
& $Acceptance init --context C:\VmInputs\en-US.json --cli C:\ReviewedBuild\ssk.exe --service C:\ReviewedBuild\ssk-svc.exe --out C:\VmEvidence\run-en-US
```

Initialization fingerprints the three binaries without executing them, generates
a run ID and writes the context/catalog binding. All 49 cases start as `not_run`.
Pin the resulting `run_sha256` and `head_sha256` in a separately controlled review
record. The exact binary hashes distinguish local changes even when the source
revision is unchanged. Changing the tested build/OS/distribution requires a new run.

## Execute and review one case

Use the matrix and corresponding operational contract for the actual experiment.
Collect timestamps around the experiment, for example with
`[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()`. Record the exact commands,
principal, expected behavior, observed result, exit codes and relevant revisions
in reviewed evidence. A granted command's `Accepted` response is asynchronous;
observe its terminal status and OS evidence before deciding an outcome.

For H02, use the granted standard-user session to query `ssk --json winhost vpn
status company-managed`, prepare using the freshly observed VPN revision, query
until the held outcome, then stop using the current revision and observe OS exit.
Use the actual approved profile ID. Follow [the broker contract](OPENVPN_BROKER_CONTROL.md)
for command syntax and uncertain-result retries. A prepare acceptance alone is
insufficient for H02. Do not release HOLD; application tunnel traffic remains unavailable.

For H03, use separate ungranted/admin sessions and record the refused requests
alongside principal identity. For interrupted configuration/backup cases, follow
[exact restoration](OPENVPN_CONFIGURATION_RESTORE.md) and
[encrypted backups](OPENVPN_CONFIGURATION_BACKUP.md). H04/H07/H09 and power-loss
boundaries still need a reviewed debugger/hypervisor procedure; the recorder
provides no fault-injection switch. A boundary not actually reached is blocked.

Review and sanitize copies of the observations before submitting them. Each
evidence file must be nonempty UTF-8 text, at most 256 KiB, with a simple `.txt`
or `.json` basename. Up to eight files are accepted per attempt. Required categories
are printed by `matrix`:

| Category | Expected reviewed content |
|---|---|
| `cli` | Commands, exit codes and sanitized JSON/status outputs |
| `acl` | Owner/SID/DACL observations and allowed/refused access outcomes |
| `journal` | Sanitized inspection/events, revisions, digests and pending-state observations |
| `process` | PID/creation-time/exit observations and containment behavior |
| `network` | Reviewed interface/route/DNS/packet observations, excluding payload secrets |
| `fault` | Exact injection boundary, method, timing and resulting state |
| `operator` | Principal/session facts and reviewed operational observations |

Labels are operator assertions; the recorder checks their presence, not whether
a file actually proves the claimed category. It rejects common PEM/credential
markers and binary content as an additional guard. This filter is deliberately
conservative and incomplete: it does not replace human review, and can reject
diagnostic text merely containing a sensitive marker. Retain raw sensitive
evidence separately under the incident policy; submit reviewed extracts here.

Fill [the observation template](examples/openvpn-acceptance-observation.json).
Example structure for an actually completed H02, with real epoch timestamps and
observations substituted before use:

```json
{
  "schema": 1,
  "case_id": "H02",
  "outcome": "passed",
  "started_unix_ms": 0,
  "ended_unix_ms": 0,
  "observed": "REPLACE with measured held-session and OS-exit observations.",
  "sanitized": true,
  "evidence": [
    {"file": "held-and-stop.json", "kind": "cli"},
    {"file": "process-exit.txt", "kind": "process"}
  ]
}
```

Zero timestamps are intentionally invalid. The test must start after the run was
created, finish after it started and finish before recording. Keep clocks correct;
the tool does not repair timestamps. `blocked` and `failed` also require a written
observation. A blocked prerequisite may have no files; a pass requires every
catalogued category. J07, D08 and B06 cannot be marked passed while their required
product/operating capabilities remain unimplemented.

```powershell
& $Acceptance record --bundle C:\VmEvidence\run-en-US --observation C:\VmInputs\H02.json --evidence-dir C:\VmReviewed\H02
& $Acceptance report --bundle C:\VmEvidence\run-en-US
```

After each append, retain the returned head separately. A retest appends a new
attempt. Earlier evidence remains checked and retained; the latest outcome governs
that case's current coverage. A later failure or block supersedes a previous pass.
No command edits, deletes, force-completes or skips an existing attempt.

## Verify both locales and interpret exit status

Use a distinct de-DE run with the same pinned binaries, OS build, source state,
distribution and driver. Principal SIDs and initial configuration hashes can differ
because the VMs have different identities. Verify both complete histories against
their independently retained heads:

```powershell
& $Acceptance report --bundle C:\VmEvidence\run-en-US --expected-head <retained-en-head>
& $Acceptance check --en-us C:\VmEvidence\run-en-US --de-de C:\VmEvidence\run-de-DE --expected-en-head <retained-en-head> --expected-de-head <retained-de-head>
```

| Command/result | Exit status |
|---|---|
| `matrix`, `init`, `record`, `report` succeeded | 0; structural success, not test/release approval |
| Invalid input, missing/changed evidence, partial attempt or mismatched head/build | 2, typed JSON error, no success report |
| `check` verified the bundles but at least one locale/case is incomplete | 3 with coverage details |
| `check` has every case passed in both locales | 0 for coverage only; currently unreachable while prerequisite cases remain blocked |

`release_ready` is always false in this increment. Tunnel enforcement, deployment,
external key/journal custody, incident procedures and actual review decisions
remain separate release gates. A structurally valid local hash chain is not a
signature or independent proof. Without a trusted retained head, removal of a
whole tail or rewriting the entire bundle cannot be ruled out.

## Storage, interruptions and limits

The bundle contains immutable `run.json` and numbered `attempts/000001`, etc.
Each attempt contains copied `evidence-01.txt` files and a final `record.json`
binding observation, evidence lengths/hashes, run hash and previous head. Names
must be canonical/contiguous; unknown files are refused. JSON schemas reject
unknown and duplicate fields. JSON records are limited to 64 KiB and runs to
256 attempts. Evidence is bounded to 512 MiB per full run, plus metadata. Verification
reads every retained proof; large-run timings remain to be measured.

An atomic new-directory claim serializes competing writers for an attempt slot.
Files are written with exclusive new-file creation and synced; the record is
written last. A crash may leave a partial run/attempt, which remains blocked and
is never silently removed or resumed. Preserve the whole bundle and external head,
investigate, and begin a separately identified run if required. Copy the complete
bundle for review only after recording has stopped. No whole-transaction power-loss
or hostile-administrator protection is claimed. Work only in a controlled evidence
directory; these filesystem checks are not a sandbox against an active local attacker.

The recorder and its tests are included in the existing Windows/Linux workspace
CI commands. Local unit/subprocess tests are evidence about this tool's behavior,
not observations for the VM matrix. Actual privileged acceptance remains pending.
