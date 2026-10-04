# RUNBOOK — validating the real Windows 11 backends (`ssk-winhost`)

This is the operator's last-mile guide: how to actually exercise the three
privileged Windows backends on a real Windows 11 machine. The code is verified
to **compile** for Windows and its pure logic is unit-tested on every platform
(and natively on Windows in CI), but the *privileged effects* — installing a
firewall rule, enumerating live flows, registering a service — require
Administrator on real hardware and are validated here, by you. Nothing in the
build claims these effects happened; this runbook is where they are confirmed.

Each action is **reversible** and records a rollback receipt, so every "do"
step below has an exact "undo".

## 0. Prerequisites

- Windows 11.
- `rustup`, with the **MSVC host** selected:
  `rustup set default-host x86_64-pc-windows-msvc`. Do **not** run
  `rustup default <channel>` for this repo — `rust-toolchain.toml` pins the
  toolchain (1.95.0) and rustup installs it automatically on the first cargo
  invocation, overriding whatever default you set.
- Visual Studio Build Tools with "Desktop development with C++" — it provides
  the linker and the `ml64.exe` that `blake3` needs.
- An **elevated** terminal (right-click → *Run as administrator*) for the
  kill-switch and service steps. `capture` and `doctor` work unelevated but see
  more with elevation.
- Elevate as the **same user account** you built with. Several steps persist
  state under `%TEMP%\ssk-winhost\`, and elevating into a *different* admin
  account gives you a different `%TEMP%` — the rollback receipts written by one
  account are then invisible to the other. (Moving that state to
  `%ProgramData%` is tracked as P1 in `docs/WINDOWS_PRODUCT_ROADMAP.md`.)

## 1. Build

```powershell
cargo build --release -p ssk-winhost -p ssk-cli
```

This produces two executables under `target\release\`:

- `ssk.exe` — the CLI, including the `ssk winhost` subcommands.
- `ssk-svc.exe` — the minimal service host the Service Control Manager launches.

> `target\release\` is inside your build tree, which your own user account can
> write to. That is fine for running the CLI. It is **not** fine as the home of
> a service binary — see §4, which copies `ssk-svc.exe` somewhere protected
> before registering it.

Confirm the backends are present on this build:

```powershell
.\target\release\ssk.exe --json winhost doctor
```

Expect `"platform_supported": true`. (On a non-Windows build it is `false` and
every privileged action below returns a typed "requires Windows" error instead
of a silent success.)

## 2. Live flow capture (IP Helper) — no elevation required

```powershell
.\target\release\ssk.exe winhost capture
```

**Expect:** a non-zero `flows captured: N`, each line an active TCP/UDP endpoint
as `tcp://<remote-ip>:<port>` / `udp://<local-ip>:<port>`. Cross-check against
the OS:

```powershell
netstat -ano | Select-String "ESTABLISHED"
```

The remote endpoints `ssk winhost capture` prints should correspond to the
connections `netstat` shows. This is **connection/flow level** (who is talking
to whom), not packet capture — no payload bytes are read (payload-neutral by
construction). Packet-level capture (WinDivert/WFP) is a documented deeper tier,
not built here.

## 3. Firewall kill-switch (elevated) — sever and restore all egress

> ⚠️ This really cuts this machine's outbound network. Do it on a host where
> that is safe (you keep console/RDP-independent access), or expect to lose
> remote connectivity until you release it.

> **Two known defects apply to this section as written** — both recorded in
> `docs/WINDOWS_PRODUCT_ROADMAP.md` and both owned by P1, neither fixed by the
> service-install work in §4:
>
> - **`engage` fails on non-English Windows** (§1.4). It matches an English
>   `netsh` string, so on e.g. a de-DE host it aborts with
>   `KILLSWITCH_ENGAGE_FAILED` *before adding any rule*. The suggested next
>   step ("requires Administrator") is misleading — elevation is not the
>   problem.
> - **The rollback receipt lives in user-writable `%TEMP%` and is not
>   integrity-checked on load** (SEC-1, §2). Losing it leaves you with no
>   supported way to release the switch; a planted one is trusted. Until P1
>   lands, note the rule name from the `netsh` check below so you can recover
>   by hand.

**Engage** (sever):

```powershell
.\target\release\ssk.exe winhost killswitch engage --scope all-egress
```

**Confirm the rule exists** (the name is `SSK-KillSwitch-all-egress-<digest>`):

```powershell
netsh advfirewall firewall show rule name=all | findstr /i SSK-KillSwitch
```

You should also observe egress actually blocked (e.g. `curl https://example.com`
now fails). The command persisted a rollback receipt under
`%TEMP%\ssk-winhost\killswitch-all-egress.json`.

**Release** (restore) — deletes *exactly* the rule engage created, nothing else:

```powershell
.\target\release\ssk.exe winhost killswitch release --scope all-egress
```

**Confirm the rule is gone** (the `findstr` above now prints nothing) and egress
works again. The exact-rollback property is the point: `release` matches on the
rule *name* alone, so no other firewall rule on the host is touched.

## 4. Windows service lifecycle (elevated)

> ### ⚠️ Read this before you install anything
>
> This service runs as **LocalSystem** — the most powerful account on the
> machine. Windows starts it by re-reading the file path you register, every
> time it starts. It does not remember the file you had; it remembers the
> *path*.
>
> So whoever can write to that path decides what runs as SYSTEM. If you point
> the service at your build tree, then **your own ordinary, non-administrator
> programs can overwrite `ssk-svc.exe`** — because your build tree belongs to
> you, not to Administrators. Anything on your machine running as you (a
> malicious npm postinstall, a macro, a browser exploit) can drop its own code
> there and wait. The next service start hands it SYSTEM. Nothing prompts, and
> nothing looks unusual.
>
> The same goes for the *folder*: if unprivileged code can create files next to
> `ssk-svc.exe`, it can plant a DLL that the service loads at startup. The
> binary does not have to be touched at all.
>
> **Earlier versions of this runbook told you to install from
> `.\target\release\ssk-svc.exe`. That instruction was the vulnerability**
> (SEC-2 in `docs/WINDOWS_PRODUCT_ROADMAP.md` §2). The procedure below installs
> from a directory that only Administrators and SYSTEM can write to, which is
> what makes "runs as SYSTEM" safe.
>
> `ssk winhost service install` now enforces this. Before it contacts the
> Service Control Manager at all, it reads the owner and DACL of the image
> file, its folder, and **every** folder above it, and refuses unless all of
> them are owned by — and writable only by — SYSTEM, Administrators or
> TrustedInstaller. It also refuses relative paths, network (UNC) paths, and
> paths that run through a junction or symlink. If it cannot read a DACL, it
> refuses; the check never guesses in your favour.

### 4.1 Put the service binary somewhere protected

In the **elevated** terminal. `C:\Program Files` is used because Windows
already gives it the right permissions and every folder created inside it
inherits them.

```powershell
New-Item -ItemType Directory -Force "C:\Program Files\ScorpioSync" | Out-Null
Copy-Item .\target\release\ssk-svc.exe "C:\Program Files\ScorpioSync\" -Force
```

Check it came out right before installing — this is the whole point of the
step, so do not skip it:

```powershell
# Owner, as a SID -- account *names* are localized (de-DE prints
# "VORDEFINIERT\Administratoren"), SIDs are not.
(Get-Acl "C:\Program Files\ScorpioSync").GetOwner([System.Security.Principal.SecurityIdentifier]).Value

icacls "C:\Program Files\ScorpioSync"
```

The owner SID must be exactly one of:

| SID | Principal |
|---|---|
| `S-1-5-32-544` | `BUILTIN\Administrators` |
| `S-1-5-18` | `NT AUTHORITY\SYSTEM` |
| `S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464` | `NT SERVICE\TrustedInstaller` |

Anything else — including your own admin account — is refused.

In the `icacls` output, `Users` / `Authenticated Users` / `Everyone` (whatever
they are called in your display language) must have **read and execute only**
(`(RX)` or `(GR,GE)`). If any of them has `(F)`, `(M)`, `(W)`, `(D)` or `(DC)`,
stop — the directory is not protected and the install will (correctly) be
refused.

Two things that commonly go wrong, and their fixes:

- **Owner is your own account, not Administrators.** Some group policies set
  the token owner to the user even when elevated. Fix:
  `takeown /f "C:\Program Files\ScorpioSync" /a` (`/a` assigns ownership to the
  Administrators *group*, which is what the check wants — a personal admin
  account is not good enough, because that account's SID stays enabled in its
  own unelevated processes and an owner can always rewrite the DACL).
- **You picked `%ProgramData%` instead.** Do not. `C:\ProgramData` passes down
  a `Users:(WD,AD)` grant, so its subfolders are writable by ordinary users
  despite living outside a user profile. The same is true of any folder you
  create directly at `C:\`, which inherits `Authenticated Users:(M)` from the
  drive root. Both are refused, and both should be.

Do not "fix" a refusal by loosening permissions. Loosening them is the bug.

### 4.2 Install

Pass the **absolute** path to the copy you just made:

```powershell
.\target\release\ssk.exe winhost service install --exe "C:\Program Files\ScorpioSync\ssk-svc.exe"
```

**Confirm** in the SCM (the service name is `SSKHost_<host-id-16hex>`):

```powershell
sc query type= service state= all | findstr /i SSKHost
```

or open `services.msc` and look for the SSK host service. Confirm the
registered path is the protected one, not the build tree:

```powershell
sc qc SSKHost_<host-id-16hex>    # BINARY_PATH_NAME must be the Program Files path
```

The install persists a receipt at `%TEMP%\ssk-winhost\service-install.json`.
`uninstall` needs that file — keep it, and see the note in §0 about elevating
as the same account.

### 4.3 What a refusal looks like

If the image path is not protected, install fails **before** the SCM is
touched — nothing is created, started or changed. The error names the offending
component and the principal that controls it. Two real examples, captured
unelevated on Windows 11 (exit code 21, machine code `SERVICE_INSTALL_FAILED`
in `--json` mode):

The old, unsafe instruction:

```
> ssk winhost service install --exe .\target\release\ssk-svc.exe
error(WinHost/21): privileged helper failed: refusing to register a LocalSystem service
for image path '.\target\release\ssk-svc.exe': the path is not absolute (an absolute
drive-rooted path with no '.' or '..' component is required). ...
next: Live effects require Windows 11 and an elevated (Administrator) shell.
```

An absolute path into a user-owned directory:

```
> ssk winhost service install --exe C:\Users\me\AppData\Local\Temp\demo\ssk-svc.exe
error(WinHost/21): privileged helper failed: refusing to register a LocalSystem service
for image path 'C:\Users\me\AppData\Local\Temp\demo\ssk-svc.exe':
'C:\Users\me\AppData\Local\Temp\demo\ssk-svc.exe' is owned by S-1-5-21-...-1001, which is
not SYSTEM, Administrators or TrustedInstaller; an owner holds implicit WRITE_DAC and can
grant itself full control. ...
next: Live effects require Windows 11 and an elevated (Administrator) shell.
```

> **Ignore that `next:` line here.** It is a generic hint attached to every
> `winhost` error and it is wrong for this one: elevation is not the problem
> and re-running elevated will not change the outcome. Move the binary
> somewhere protected (§4.1) instead. (Making that hint specific to the failure
> is a `ssk-cli` change, tracked as a follow-up, not done here.)

If you want to see the check work without installing anything, run the crate's
own tests — they exercise it against this machine's real ACLs, unelevated:

```powershell
cargo test -p ssk-winhost --lib service::
```

### 4.4 Start / stop / uninstall

These take no `--exe`. The service name is derived from the host manifest, not
from a path, so they work from any directory:

```powershell
.\target\release\ssk.exe winhost service start
.\target\release\ssk.exe winhost service stop
```

After `start`, `sc query SSKHost_<...>` should show `STATE : 4 RUNNING`.

**Uninstall** — deletes the service **only if this install created it** (if the
service already existed before `install`, uninstall leaves it in place — we
never destroy what we did not create):

```powershell
.\target\release\ssk.exe winhost service uninstall
```

Confirm it is gone from `services.msc` / `sc query`, then remove the copy you
made:

```powershell
Remove-Item "C:\Program Files\ScorpioSync\ssk-svc.exe"
```

> Rebuilding does **not** update an installed service. `cargo build` writes to
> `target\release\`; the SCM starts the copy in `C:\Program Files\ScorpioSync\`.
> To pick up a new build, stop the service, copy the new binary over, and start
> it again. (An installer that sequences this properly is P6.)

## 5. End-to-end decision over a fixture (any platform)

The library decision stack is runnable independent of the privileged effects:

```powershell
.\target\release\ssk.exe --json system run --fixture clean
.\target\release\ssk.exe --json system run --fixture sensitive   # exits 20 (fail-closed deny)
```

## What is and is not proven

- **Proven by the build/CI:** the Windows FFI compiles against the real Windows
  API (MSVC), clippy passes over the `cfg(windows)` code, and the pure logic
  (rule-name/service-name derivation, connection-table parsing, receipt
  encoding, error classification) passes its unit tests natively on Windows.
- **Proven by `cargo test -p ssk-winhost`, unelevated, on a real machine:** the
  §4 image-path check reads real Windows DACLs. Its tests assert that a stock
  protected system binary (`%SystemRoot%\System32\svchost.exe`) is *accepted*
  across its whole ancestor chain, that a directory under `%TEMP%` is
  *refused*, that a nonexistent path is *refused* rather than skipped, and that
  `WindowsServiceHelper::install` produces that refusal without contacting the
  SCM. What those tests demonstrate is that the gate says **no** correctly.
- **Proven only by running this runbook on your machine:** that the firewall
  rule is actually installed/removed, that real flows are enumerated, that the
  service registers with and is controlled by the SCM, and that a binary placed
  in `C:\Program Files\ScorpioSync\` **passes** the §4 check and installs.
  Creating that directory needs elevation, so the accept-and-install path has
  never been executed — only the refusal paths have. Those require
  Administrator on real hardware and are yours to confirm with the checks above.
- **Not proven by anything, and not claimed:** that the registered binary is the
  one this project built. The §4 check establishes *who can write the file*, not
  *what the file is*. There is no Authenticode verification anywhere in this
  repo; signing is P6.

If any step behaves differently from what is described here, that is a real
finding — capture the exact command, the CLI's `--json` output, and the
corresponding OS check (`netsh` / `sc` / `netstat`) output.
