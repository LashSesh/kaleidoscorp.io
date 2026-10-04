# OpenVPN recovery contract — 2026-09-22

The service supports `ssk winhost vpn recover <profile> --expected-revision <n>`
for an interrupted, recorded attempt. It proves that the old child has ended,
cleans that attempt's two private launch files, and records the result before
allowing another prepare. It does not reconnect, release HOLD, kill a recorded
PID, reset a journal, or authorize network traffic. `OPENVPN_NOT_READY` remains.

## Evidence before execution

The production Windows broker path now orders startup as follows:

1. Authorize the SID/profile/verb and synchronize the prepare intent. Clear any
   previous attempt's identity and recovery proof in this same intent.
2. Claim fresh private launch files under a random 128-bit ID; retain their locks.
3. Create the process with `CREATE_SUSPENDED`, atomically associated through
   `PROC_THREAD_ATTRIBUTE_JOB_LIST` with the owned, non-inheritable unnamed job.
   Kill-on-close, active-process limit one and no breakaway remain enforced.
4. Read PID and creation FILETIME from the owned process handle. Synchronize a
   `ProcessCreated` journal event containing both and the launch-file ID.
5. Check cancellation again, then resume the owned primary thread. Accept only
   the expected previous suspension count of one. The normal authenticated
   management startup runs next and remains in HOLD.

A failed identity read, refused/failed journal append, cancellation or failed
resume triggers termination through the owned job, with bounded OS exit
confirmation. No process is resumed after a refused identity callback. A broker
backend returning success without identity is an audit fault, never readiness.
The former unaudited `PreparedVpn::prepare` convenience API has been removed;
production preparation is crate-internal and uses the tracked identity callback.

Creation time comes from [GetProcessTimes](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesstimes).
The startup gate checks [ResumeThread's previous suspension count](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-resumethread).
The [job containment contract](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects)
limits descendants and arranges crash termination; recovery still requires an
observation rather than treating that contract as a recorded exit.

## Explicit recovery

`recover` needs its own protected policy grant; previous status/prepare/stop
rights do not imply it. The current profile and revision must match. The command
is accepted only from `recovery_required`, with a valid recorded identity and a
healthy journal. Missing identity returns `EvidenceUnavailable` before any effect.
Nonce, idempotency, session limits and asynchronous acceptance use the existing
[broker contract](OPENVPN_BROKER_CONTROL.md). `recovering` prevents overlapping
mutation, including when a process observation races with the incoming intent.

After the recovery intent is synchronized, the worker opens the recorded PID
with only `PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE`, without
inheritance. It holds this handle while comparing creation time and querying
exit. It never requests process termination/write rights or sends management
commands to a recorded endpoint. These are [read/query process rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights).

| Observation | Outcome |
|---|---|
| Same creation time and signaled process handle | `process_exited` evidence |
| PID no longer exists (`ERROR_INVALID_PARAMETER`, nonzero validated PID) | `pid_absent` evidence |
| Different creation time at that PID | `pid_reused` evidence; replacement remains untouched |
| Same identity still running | `process_alive`; remain blocked |
| Access denied, failed time query or other unexpected OS result | `process_query`; remain blocked |

If this worker still owns the original session, it first requires exit observed
through that original owner and drops its file guards before recovery cleanup.
Recovery itself does not request termination. Service shutdown and ordinary
supervision retain their existing owned-job termination duty.

Only after exit proof does cleanup open `run-<recorded-id>.pw` and
`run-<recorded-id>.ovpn` in the fixed protected profile store. It verifies directory
security, rejects reparse points and hardlinks, checks file confidentiality and
holds a handle denying write/delete sharing. Deletion uses that same checked
handle through [SetFileInformationByHandle/FileDispositionInfo](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfileinformationbyhandle),
with explicit DELETE access. There is no glob, directory scan, supplied path or
recursive deletion. Already missing files are safe; partial cleanup is retryable.
Deletion is not secure erasure.

Success is `idle` with `exit_confirmed: true`, recorded process identity and a
`recovery_evidence` category. A result is visible under the broker mutex only
after the append succeeds. Cleanup errors remain `recovery_required` with
`recovery_failure: cleanup`. An audit error latches the normal audit fault and
blocks further mutations, even if OS verification and cleanup already succeeded.
A crash during recovery is replayed as `recovery_required` on the next boot;
there is no automatic replay of the command. Query a fresh revision and submit a
new operation after reviewing status. Idempotency keys remain session-scoped.

## Compatibility and limits

VPN wire version is now **3**; version 2 clients/services must be upgraded together.
There is no downgrade. Kill-switch wire version 1 remains independent. Journal
storage now uses [segmented retention](OPENVPN_JOURNAL_RETENTION.md), whose new
records have schema 2. Old schema-1 records remain readable with their exact
serialization and hashes preserved. An older service refuses the new schema,
preventing it from ignoring later segments. Compatibility is in the upgrade
direction; downgrade or an already-full legacy journal needs reviewed migration.


A crash between suspended process creation and durable `ProcessCreated` leaves
no recorded identity. The process never received permission to execute, and job
closure provides containment, but recovery deliberately does not equate these
facts with observed OS exit. Such an attempt remains blocked. Old interrupted
version-2 attempts have the same missing-evidence restriction. Corrupt/torn
journals still disable the VPN domain; `recover` cannot repair them. Preserve
journal and protected leftovers for investigation; deleting them to clear the
alarm is not a supported workflow. Local bounded retention/rollover is implemented;
external archival/pruning/restore and a reviewed operator procedure for
missing-evidence incidents remain release gates.

The journal is protected local evidence, not an externally anchored audit trail.
An administrator controlling the store can still forge/truncate history. Process
identity is the Windows PID/creation-time identity, not remote attestation.

## Validation

A missing/damaged committed configuration can prevent the service from loading
the grants needed for process recovery. [Offline exact restoration](OPENVPN_CONFIGURATION_RESTORE.md)
can recover that same committed document without changing any recorded process
identity, exit proof or recovery phase. It never selects an older grant set or
substitutes for process `recover`; missing OS evidence remains blocked.

Package-selection interruption is a separate offline administrative workflow:
[deployment reconciliation](OPENVPN_PACKAGE_DEPLOYMENT.md). A pending package
intent blocks VPN service startup. Package operations preserve process history
and cannot substitute for a granted process `recover` or clear missing OS evidence.

Automated checks cover durable identity before execution, journal compatibility,
separate recovery grants, wrong profiles, missing evidence, replay/idempotency,
concurrent exit versus recovery, failed intent/result writes, live-process refusal,
interrupted recovery and clearing old identity before a new attempt.
Windows tests use actual suspended harmless processes, show execution only after
resume, confirm audit refusal/cancellation prevents execution, check PID-time
mismatch without killing its occupant, and verify exact/partial/unsafe-file cleanup.
A broker/file-journal test restores a crash prefix in a temporary fixture after
confirmed child termination, recovers it and prepares a fresh attempt. Separate
existing job tests cover actual abrupt owner death. This is not an SCM crash test.

Temporary ACL observations in these launch tests use private injected probes.
Production paths always use real probes; LocalSystem/cross-user and actual OpenVPN
acceptance remain [unexecuted VM work](OPENVPN_VM_ACCEPTANCE.md). No VPN client,
service, driver, route or firewall was installed or activated on the workstation.

Validation results are recorded in the latest section of the
[restart assessment](RESTART_ASSESSMENT_2026-09-21.md).
Local logs: `target/restart-audit/vpn-recovery-*.log`.
