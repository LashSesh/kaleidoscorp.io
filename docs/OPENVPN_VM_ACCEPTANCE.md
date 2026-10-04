# OpenVPN Windows VM acceptance — planned, not executed

This is the acceptance plan for the held broker and recovery path as of
2026-09-22. **No row below has been executed against a real OpenVPN distribution
or LocalSystem service.** Passing the local fixture tests is not this acceptance.

The repository already has Windows/Linux build, test and Clippy CI, real harmless
Windows process/job/pipe tests, and the older
[P1 elevated VM checklist](OPERATOR_VM_VALIDATION.md). The separate
[`ssk-vpn-acceptance` evidence recorder](OPENVPN_ACCEPTANCE_TOOL.md) now binds
reviewed observations to builds/VMs and verifies all retained evidence for both
locales. It executes no test or privileged action. Dedicated VM provisioning and
fault-injection automation remain open; the older checklist does not cover this
new control domain.

## Environment and evidence

No separate test environment was available at the 2026-09-22 continuation. The
[development transfer kit and read-only host probe](OPENVPN_TEST_KIT.md) prepare
the handoff to a future host. Kit integrity or sufficient host resources do not
satisfy the VM prerequisites or count as executed cases.

Use a disposable Windows VM with a clean snapshot, isolated test network and VM
console access. Record exact Windows build, locale, service/CLI build revision,
OpenVPN distribution/version, executable and DLL hashes, driver version, policy
revision, test start/end times and VM snapshot ID. Run with en-US and de-DE.
Use separate principals: LocalSystem service, granted standard user, ungranted
standard user, and an administrator without a VPN grant. Use test-only credentials.

Before execution, provide the installation/provisioning procedure for protected
profiles/control policy and the approved distribution/driver. The repository now
provides [offline pinned-bundle deployment](OPENVPN_PACKAGE_DEPLOYMENT.md),
[whole profile/grant configuration deployment](OPENVPN_CONFIGURATION_DEPLOYMENT.md)
and profile-store provisioning, but no complete product/driver installer or PKI lifecycle.
Do not interpret this plan as evidence of deployment acceptance. The
profile parser's fixture credentials are deliberately invalid and cannot be used
for a working VPN acceptance profile. Missing prerequisites leave a row blocked.

Retain sanitized CLI JSON, service diagnostics, journal records, process identity
and exit observations, file/ACL snapshots, route/DNS/interface snapshots and packet
captures appropriate to each row. Protect raw journals and profile files; do not
copy private keys or management passwords into reports. Record pass/fail/blocked
with evidence paths and actual observations, never merely a checked box.

## Held control and recovery matrix

| ID | Scenario | Required observation |
|---|---|---|
| H01 | Install/start under LocalSystem with approved pinned distribution | Service and CLI v3 handshake; real protected-store probes pass; initial status is idle |
| H02 | Granted user prepare, query, disconnect and stop | Asynchronous acceptance; authenticated held session stays service-owned; stop observes OS exit |
| H03 | Ungranted user/admin, wrong profile/verb/token, obsolete VPN v2 | Refusal before effect; no implicit admin or boundary grant; v1 boundary still works |
| H04 | Observe suspended creation and identity journal ordering | ProcessCreated is durable before resume; audit failure before resume permits no execution |
| H05 | Kill service after ProcessCreated, during authentication, after held result | Job child ends; restart reports recovery_required; no automatic prepare or tunnel release |
| H06 | Recover after H05 with explicit grant and fresh revision | Recorded identity matches evidence; only its two run files removed; durable result before idle; next prepare gets a new launch ID |
| H07 | Crash after process creation but before identity sync | Restart remains blocked with missing evidence; no override or journal reset |
| H08 | Recovery with still-live recorded child or unavailable OS proof | Recovery stays blocked; no PID-based termination or attachment |
| H09 | Crash during recovery before/after one deletion and before result sync | Restart remains recovery_required; explicit retry is safe and preserves unrelated files/history |
| H10 | Deny/full storage at intent, ProcessCreated or result write | No unaudited execution/new permission; owned session terminated when necessary; audit fault visible |
| H11 | Corrupt/truncated journal, hardlink/reparse/nonconfidential artifact | Domain refuses unsafe state; no auto-repair or broad deletion; other control domain remains independently authorized |
| H12 | Race prepare/recover/stop from two granted users and disconnect/retry | One operation at a time; stale revisions rejected; duplicate original acceptance distinguished from current status |
| H13 | Service stop during startup and recovery; power/reboot and suspend/resume | Bounded cancellation where supported; unresolved evidence remains blocked; SCM error reflects unresolved/audit failures |
| H14 | Inspect network and driver effects while HOLD is retained | Record actual interface/route/DNS/packet behavior; no claimed application egress admission; distribution compatibility established |

Failure injection for exact H04/H07/H09 boundaries needs a reviewed VM-only
harness or debugger workflow; no production bypass switch is supplied. A test
that cannot hit its boundary is blocked, not passed. PID reuse is covered locally
with a controlled creation-time mismatch; VM reports must distinguish this from
observing actual Windows PID reuse.

## Journal retention matrix — also unexecuted

| ID | Scenario | Required observation |
|---|---|---|
| J01 | Cross record and byte boundaries under LocalSystem | Old files unchanged; next fixed segment confidential; chain/revisions continue |
| J02 | Process crash/power loss around claim, first frame and sync | Empty final segment resumes; torn data refuses; no replacement history |
| J03 | Second host and offline inspector while the service is active | Writer lock prevents overlap; stopped-service inspection changes no bytes |
| J04 | Missing segment, wrong ACL, reparse/hardlink, collision, storage full | Refusal preserves evidence and unresolved status; no unauthorized execution |
| J05 | Schema-1 upgrade with capacity and exhausted legacy origin | New schema fences old readers; full legacy migration is explicitly blocked |
| J06 | Full retained history startup and shutdown timing | Record memory usage, total verification time and SCM pending/checkpoint behavior; no unmeasured scalability claim |
| J07 | Protected backup/restore and trusted external head comparison | Snapshot verification, startup fencing and resumable reconstruction into quarantine now exist; remains blocked until live activation and external custody procedures are implemented and exercised |

The [retention contract](OPENVPN_JOURNAL_RETENTION.md) defines the local limits.
A shrinking tail is not detectable solely from the remaining local chain; external
anchoring and retention policy must be evaluated separately from parser integrity.

## Package deployment matrix — also unexecuted

| ID | Scenario | Required observation |
|---|---|---|
| D01 | Elevated provision/stage on clean en-US/de-DE Windows; standard-user refusal | Real owner/inherited ACL checks pass only for the authorized protected store; no executable starts |
| D02 | Independently approved release, changed DLL/manifest, extra files, hardlink/reparse/unsafe target | Exact approved bytes copied or refusal before selector change; distribution/driver compatibility separately established |
| D03 | Active service/second deployer, pending process recovery, stale expected selector | Exclusive ownership and state comparison prevent overlapping update |
| D04 | First selection, update, explicit staged rollback | Previous bundles preserved; selector digest, actor SID and durable intent/result agree; held launch verifies chosen images |
| D05 | Process crash/power loss before/after selector move and result sync | Startup remains blocked on pending intent; explicit reconciliation confirms only verified old/new state; torn journal stays blocked |
| D06 | Storage/ACL failure during copy, temporary write, intent, move or result | No false success; partial artifacts retained; prior version preserved where selection did not occur |
| D07 | Old binary downgrade, foreign selector or damaged selected bundle | No silent history acceptance, state reset or automatic rollback; actionable refusal |
| D08 | Long-term package accumulation and partial-stage recovery | Remains blocked until reviewed retention/garbage-collection and incident procedures exist |

The local tests inject interruption at filesystem boundaries; they do not prove
power-loss durability, real inherited ACL behavior or actual distribution compatibility.

## Configuration matrix — also unexecuted

| ID | Scenario | Required observation |
|---|---|---|
| C01 | Stage a private approved snapshot under elevated en-US/de-DE accounts | Real source and inherited destination confidentiality checks pass; standard-user/readable source refused |
| C02 | Select updated profile and a different granted SID, then restart LocalSystem | Pipe SID list, policy decisions and held-launch profile agree with one committed digest; old SID is denied |
| C03 | All-grants revocation and explicit older-snapshot selection | Empty managed snapshot denies all; rollback restores only the reviewed snapshot, including its grants |
| C04 | Service startup concurrent with update or pending package/configuration intent | One lifetime journal owner; no partially loaded or uncommitted authorization |
| C05 | Crash/power loss at temporary write, intent sync, move and completion | Correct blocked state; matching-domain reconciliation confirms only verified old/new bytes; torn journal remains blocked |
| C06 | Delete/alter active snapshot after migration while legacy files remain | No resurrection of legacy permissions; startup refuses the mismatch |
| C07 | Legacy recovery with missing profile, and managed snapshot restart compatibility | Recovery authorization remains independent of missing legacy credentials; managed files are checked against journal digest |
| C08 | Logs, reports, crash dumps, backups and staged/temporary secret retention | CLI/audit omit secret material; OS dump/backup protections and reviewed archival/cleanup procedures have separate evidence |

No row is passed by the local fixtures, which inject ACL observations and do not
exercise cross-user access or real LocalSystem OpenVPN startup.

## Configuration restoration matrix — also unexecuted

| ID | Scenario | Required observation |
|---|---|---|
| F01 | Diagnose and restore from retained/external confidential copies under elevated en-US/de-DE accounts | Real source/evidence/temp ACL checks pass; report omits secrets; standard-user access and unsafe files refused |
| F02 | Missing/malformed/different active document, stale expectations and older backup | Only exact committed bytes restored; original bytes retained as protected evidence; revoked grants never return |
| F03 | Restore with an unresolved recorded child, then restart LocalSystem | PID, creation time, launch ID and exit/recovery state preserved; fresh prepare stays blocked until separately authorized process recovery |
| F04 | Process crash/power loss before/after evidence, intent, move and completion | Pending state blocks startup; explicit restoration reconciliation confirms only original/committed state; no journal truncation or evidence deletion |
| F05 | Missing/altered evidence, unknown active bytes, hardlinks, reparse points, storage/ACL failure | No false completion or forced repair; evidence and unresolved state preserved for incident handling |
| F06 | Diagnose while service owns journal; intact no-op; older binary after restoration | Exclusive ownership prevents overlap; no-op changes no files/events; older reader refuses new repair variants |

The [restoration contract](OPENVPN_CONFIGURATION_RESTORE.md) covers the active
configuration only. It does not satisfy J07 journal archival/restoration, key
custody, secret cleanup or complete disaster-recovery acceptance. No F row has
been executed in a real Windows VM by the local fixture suite.

## Encrypted configuration backup matrix — also unexecuted

| ID | Scenario | Required observation |
|---|---|---|
| B01 | Elevated key/archive creation on approved local volumes, en-US/de-DE; standard-user reads/writes | Real parent/ancestor/file ACL checks and inherited confidentiality hold; standard-user access denied |
| B02 | Copy archive and separately escrowed key through the approved storage procedure | Readback authentication against current commitment succeeds after transfer; catalog and key reference match; no plaintext in reports |
| B03 | Lose active and staged plaintext while preserving verified journal/key/archive | Direct archive restoration returns exact committed bytes, preserves original evidence and process state; normal recovery still required |
| B04 | Wrong/lost key, single-byte corruption, older archive after revocation | Refusal before restore effects; no password override, old-grant resurrection or journal reset |
| B05 | Disk full/access loss/power interruption during key/archive creation and restore | Existing files never overwritten; incomplete artifacts never reported successful; restore uses existing pending/evidence reconciliation |
| B06 | Operational inventory, recovery exercise and key/secret retention policy | Document key custodians, separately stored copies, verification results and access controls; unattended export audit, pruning/rotation and complete journal restoration remain blocked until implemented |

The [archive contract](OPENVPN_CONFIGURATION_BACKUP.md) defines the new format and
commands. Local tests do not establish media durability, real ACL inheritance,
key-custody effectiveness or whole-machine recovery. These rows remain unexecuted.

## Later tunnel acceptance

Tunnel release is not implemented. Verified interface binding, route/DNS policy,
kill-switch coupling and application-flow enforcement must be implemented before
running a connected-data-plane release gate. That later gate must cover IPv4 and
IPv6, DNS and routing leaks, endpoint changes, network loss, adapter replacement,
service/child crashes and suspension/resumption with packet-level evidence.
The current `OPENVPN_NOT_READY` result is expected, not an acceptance defect.

The release decision remains blocked until required rows pass, deployment/update
and external archival/pruning/restore procedures are implemented, and missing-evidence incidents
have an approved operational resolution. Restore the disposable snapshot after
each fault-injection group; preserve its evidence outside the discarded VM disk.
