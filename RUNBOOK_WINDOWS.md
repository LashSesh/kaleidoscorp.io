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
- Rust with the MSVC toolchain: `rustup default stable-x86_64-pc-windows-msvc`
  (the Visual Studio Build Tools / "Desktop development with C++" provides the
  linker and `ml64.exe` that `blake3` needs).
- An **elevated** terminal (right-click → *Run as administrator*) for the
  kill-switch and service steps. `capture` and `doctor` work unelevated but see
  more with elevation.

## 1. Build

```powershell
cargo build --release -p ssk-winhost -p ssk-cli
```

This produces two executables under `target\release\`:

- `ssk.exe` — the CLI, including the `ssk winhost` subcommands.
- `ssk-svc.exe` — the minimal service host the Service Control Manager launches.

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

**Install** — registers `ssk-svc.exe` as a service; persists a receipt:

```powershell
.\target\release\ssk.exe winhost service install --exe .\target\release\ssk-svc.exe
```

**Confirm** in the SCM (the service name is `SSKHost_<host-id-16hex>`):

```powershell
sc query type= service state= all | findstr /i SSKHost
```

or open `services.msc` and look for the SSK host service.

**Start / stop:**

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

Confirm it is gone from `services.msc` / `sc query`.

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
- **Proven only by running this runbook on your machine:** that the firewall
  rule is actually installed/removed, that real flows are enumerated, and that
  the service registers with and is controlled by the SCM. Those require
  Administrator on real hardware and are yours to confirm with the checks above.

If any step behaves differently from what is described here, that is a real
finding — capture the exact command, the CLI's `--json` output, and the
corresponding OS check (`netsh` / `sc` / `netstat`) output.
