# Operator VM Validation — the elevated half of P1

> **DISPOSABLE VM ONLY. Snapshot first.** Every leg below mutates firewall rules, ACLs or the SCM.
> **None of it has been run.** It exists because P1 was implemented and unit-tested on an unelevated
> developer machine, and the project's rule is that unexecuted code is never described as verified.
>
> Authored 2026-08-02 against the state at the end of P1.

## Why this document exists

P1 closed two privilege escalations and the non-English kill-switch break. All of it is covered by
unit tests with injected probes and scripted command runners — 721 passing tests — but the
**privileged half has never executed**: no firewall rule has ever been created or deleted by this
software, no service has ever been installed, and `icacls` has never actually locked down a store
directory. Those paths cross the UAC boundary and were deliberately not exercised on the developer's
primary machine.

This checklist is what turns "implemented and unit-tested" into "verified".

Build once on the VM:

```bash
cargo build --release -p ssk-cli -p ssk-winhost
```

Use `$SSK = <repo>\target\release\ssk.exe` throughout.

---

## LEG 0 — Locale matrix (run every leg twice)

Run everything below once on **en-US** and once on **de-DE**. A leg that passes on en-US and fails on
de-DE is the exact defect P1 exists to close.

To switch: Settings → Time & language → add Deutsch (Deutschland) → set as Windows display language →
sign out and in. Confirm with `Get-WinSystemLocale`, and check that
`netsh advfirewall firewall show rule name=nosuchrule` prints *"Keine Regeln stimmen…"*.

---

## LEG 1 — netsh exit codes that could not be measured unelevated

Informational, but it underpins the whole classifier.

| Run as | Command | Expect |
|---|---|---|
| Elevated | `netsh advfirewall firewall add rule name=SSK-KillSwitch-vmtest-0011223344556677 dir=out action=block enable=yes profile=any localip=any remoteip=any` | exit **0** |
| **Unelevated** | same `add` | **record** the exit code — this is the unknown access-denied code |
| Elevated | `netsh advfirewall firewall delete rule name=SSK-KillSwitch-vmtest-0011223344556677` | exit **0** |
| **Unelevated** | same `delete` | **record** the exit code |

**Failure looks like:** the *unelevated* `add` returning exit 0. That would break the classifier's
core premise — *exit 0 ⟹ the rule exists* — and must be reported before anything ships.

---

## LEG 2 — The P1 exit criterion: full engage → release with a rule diff (elevated)

```powershell
netsh advfirewall firewall show rule name=all > C:\vm\before.txt
& $SSK --json winhost killswitch engage --scope vmtest      # expect exit 0, "verification":"confirmed"
netsh advfirewall firewall show rule name=SSK-KillSwitch-vmtest-<digest16>; $LASTEXITCODE   # expect 0
Test-NetConnection 1.1.1.1 -Port 443                        # expect FAILURE — egress really severed
& $SSK --json winhost killswitch status --scope vmtest      # expect "verdict":"engaged"
& $SSK --json winhost killswitch release --scope vmtest     # expect exit 0, "egress_restored":true
netsh advfirewall firewall show rule name=SSK-KillSwitch-vmtest-<digest16>; $LASTEXITCODE   # expect 1
Test-NetConnection 1.1.1.1 -Port 443                        # expect SUCCESS
netsh advfirewall firewall show rule name=all > C:\vm\after.txt
Compare-Object (gc C:\vm\before.txt) (gc C:\vm\after.txt)   # expect EMPTY
```

Get `<digest16>` from step 2's JSON `rule_name`, or from `killswitch status`.

**Failure looks like:** `KILLSWITCH_ENGAGE_UNVERIFIED` (the add worked but presence could not be
confirmed — record the receipt path, then use `recover`); `Test-NetConnection` **succeeding** after
engage (the rule exists but does not block); or any diff at the end (we changed firewall state we did
not restore — the most serious outcome here).

---

## LEG 3 — Receipt-less recovery (elevated)

```powershell
& $SSK --json winhost killswitch engage --scope vmtest
Remove-Item "$env:ProgramData\ScorpioSync\state\killswitch-*.json"
& $SSK --json winhost killswitch status --scope vmtest      # expect "engaged_receipt_lost"
& $SSK --json winhost killswitch recover --scope vmtest --yes   # expect "outcome":"reverted"
netsh advfirewall firewall show rule name=SSK-KillSwitch-vmtest-<digest16>; $LASTEXITCODE   # expect 1
```

**Failure looks like:** step 3 reporting `armed` — a lost receipt reading as "nothing is severed" is
fail-open, the worst outcome for this component. Or step 4 leaving the rule in place.

---

## LEG 4 — Store provisioning and the squat refusal

**This is the leg with the least prior evidence. Run it first if you run only one.**

### 4a — The lockdown argv has never executed

Elevated, run `crates\ssk-netd-helper\scripts\verify-store-dacl.ps1`. It provisions a scratch
directory with the exact shipped argv and dumps the DACL.

Expect the resulting DACL to list **only** `NT AUTHORITY\SYSTEM` and `BUILTIN\Administrators`, with
owner `BUILTIN\Administrators`.

**Failure looks like:** `icacls` rejecting `*S-1-5-18` in a `/grant:r` argument. This argv has never
run anywhere — if it fails, **every** provision fails closed and the store can never be created.

### 4b — The DACL actually denies

From a **second, unelevated** shell: `"x" | Out-File <that dir>\probe.txt` → expect **access denied**.
If it succeeds, the DACL buys nothing.

### 4c — Squat refusal (the gap P1 closed; verify it is really closed)

On a fresh VM where `C:\ProgramData\ScorpioSync` does not exist, **unelevated**:

```powershell
New-Item -ItemType Directory "C:\ProgramData\ScorpioSync\state"
(Get-Acl "C:\ProgramData\ScorpioSync").GetOwner([System.Security.Principal.SecurityIdentifier]).Value
```

This is *expected to succeed* and to print your user's `S-1-5-21-*` SID — `C:\ProgramData` grants
`BUILTIN\Users` write with ContainerInherit, which is Windows' ACL, not ours. That is not the bug.

Then, **elevated**:

```powershell
& $SSK --json winhost killswitch engage --scope vmtest
```

**Expect a typed `STATE_DIR_UNSAFE` refusal**, naming the offending directory and its owner, with
**no firewall rule created**. The squatted directory is refused, never repaired — re-ACLing would not
revoke a handle an attacker already holds.

**Failure looks like:** engage succeeding. That would mean an unprivileged user owns the receipt store
and the product trusted it — the exact defect this leg exists to disprove. Also check
`ssk winhost doctor` reports `receipt_store.protection` as unsafe rather than ok.

> The `audit_owned_directory` predicate has **never fired through the CLI** on any machine. Every live
> state-dir refusal observed so far came from the *ancestor* gate in front of it. This leg is the
> first real exercise of it.

### 4d — Does `C:\Program Files\ScorpioSync` get the right owner?

Elevated:

```powershell
New-Item -ItemType Directory "C:\Program Files\ScorpioSync"
(Get-Acl "C:\Program Files\ScorpioSync").GetOwner([System.Security.Principal.SecurityIdentifier]).Value
```

Must print `S-1-5-32-544`. If it prints an `S-1-5-21-*` account SID, SEC-2 will refuse the *correct*
install location, and `takeown /f "C:\Program Files\ScorpioSync" /a` becomes **mandatory**, not
optional — report it, because it changes the documented install procedure.

---

## LEG 5 — SEC-2 accept-and-install (elevated)

The refusal half is heavily unit-tested; the **accept** half has never run.

1. Copy `ssk-svc.exe` to `C:\Program Files\ScorpioSync\` (after 4d).
2. `& $SSK winhost service install --exe "C:\Program Files\ScorpioSync\ssk-svc.exe"` → expect exit 0.
3. `sc.exe qc SSKHost_<id>` → `BINARY_PATH_NAME` must be exactly that path.
4. `& $SSK winhost service start` / `stop` / `uninstall` → each exit 0; then `sc query SSKHost_<id>`
   → "service does not exist".
5. **Negative:** `mklink /J C:\jtest "C:\Program Files\ScorpioSync"` then install via `C:\jtest\...`
   → expect a junction refusal.
6. **Negative:** install from a `%TEMP%` path and from `C:\ProgramData\...` → refusal in both.

**Failure looks like:** step 2 refusing a correctly-placed binary (a **false refusal** — most likely
the owner check at 4d, or a conditional/callback ACE from EDR, which the gate refuses on type alone);
or steps 5/6 succeeding.

---

## LEG 6 — Session-0 / no-console encoding (the P3 host case)

Elevated:

```powershell
schtasks /create /tn ssknetsh /ru SYSTEM /sc once /st 23:59 /tr "cmd /c netsh advfirewall firewall show rule name=nosuchrule > C:\vm\svc.txt 2>&1"
schtasks /run /tn ssknetsh
Format-Hex C:\vm\svc.txt
```

On de-DE the developer box produced UTF-8 `c3 bc` for `ü`, identically under `chcp` 850/1252/65001 and
whether redirected to a file or a pipe.

**Failure looks like:** different bytes. Because **no branch reads this text**, the consequence is a
mojibake log line rather than a wrong decision — but record it, since this is currently a de-risk
rather than a measurement.

---

## LEG 7 — CI

Confirm `cargo test -p ssk-netd-helper` passes on `windows-latest`.

> **Read this before trusting a green result.** GitHub's `windows-latest` runner executes **elevated**,
> so it *cannot* reproduce the UAC-filtered-token lockout of roadmap §5.2 — the condition that made 8
> of these tests fail on a real unelevated desktop. A green CI leg is necessary, not sufficient.
>
> There is also still **no non-English CI leg**, which P1 explicitly asks for.

---

## Cleanup / rollback

```powershell
netsh advfirewall firewall delete rule name=SSK-KillSwitch-vmtest-<digest16>
```

If you have no digest:

```powershell
netsh advfirewall firewall show rule name=all | Select-String SSK-KillSwitch
```

Then restore the VM snapshot.

---

## What remains unvalidated even after this checklist

- `is_elevated() == Some(true)` — only the `Some(false)` arm has ever executed.
- The `Elevation::Elevated` arm of `ensure_impl` against real `icacls`.
- A **live** create-then-icacls race (LEG 4c's provenance guard is verified only against injected
  doubles; the premise that the parent's `/T` scrubs a raced child's ACL is inferred from the argv,
  not observed).
- A race into the **leaf's contents** — one level deeper than the provenance guard tracks. Bounded to
  the same denial-of-rollback already documented; listed here so it is not forgotten.
- Non-Windows arms of `state_dir.rs` and `privilege.rs` are compiled by CI's Linux legs but were
  reviewed by hand only on the developer machine (only `x86_64-pc-windows-msvc` is installed there).
