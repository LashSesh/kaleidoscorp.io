# Specification — SSK Desktop GUI (Tauri) + Privileged Bridge

**Status:** Draft for review. Specification only — no implementation until approved.
**Stack decision:** Tauri v2 (Rust backend links the SSK crates; HTML/CSS/JS frontend in WebView2).
Chosen over WinUI 3 / Avalonia / egui / Slint on one decisive axis: the backend *is* Rust, so it
reuses the pure `ssk-*` controllers in-process with **zero FFI** and no re-declared DTOs. This
matches the direction the repo already carries (`docs/DESKTOP_CLIENT_ARCHITECTURE.md` names
`ssk-tauri-bridge`; `crates/ssk-ipc/src/lib.rs` anticipates "a Tauri GUI bridge").

> Honesty note on scope: this document distinguishes **[EXISTS]** (already in the tree, tested)
> from **[NEW]** (to be built). No verdict is inflated; a mis-read control state on a security
> panel is a *safety* defect, so the fail-closed rules in §7 are normative, not stylistic.

---

## 1. Purpose & non-goals

**Purpose.** A local control panel for the SSK system on Windows 11: see system state and gate
verdicts, read and verify the audit ledger, inspect connections and routes, and drive the two
privileged operations that matter — the **kill-switch** (sever/restore all outbound egress) and the
**Windows service lifecycle** (install/start/stop/uninstall).

**Non-goals (this spec).**
- The GUI holds **no privileged logic and no business logic**. It is a *view + driver* over
  existing controllers and the privileged broker. Every decision stays in the audited Rust core.
- No auto-update in v1 (the roadmap's Tauri-updater is deferred; §8).
- No MSIX in v1 (native Tauri bundle is MSI/NSIS; MSIX is a later bolt-on if enterprise
  distribution demands it — see the WinUI trade-off we deliberately declined).
- The older `docs/ROADMAP_DESKTOP_GUI.md` HTTP sketch (`POST /run`, …) is **superseded** by the
  real `ssk-ipc` Request/Response contract; the GUI speaks that, not new HTTP endpoints.

---

## 2. Architecture

Three components; two are new crates, one is the frontend.

```
┌──────────────────────────────────────────────────────────────┐
│  WebView2 frontend  (HTML/CSS/JS, framework-free)            │  unprivileged
│   renders DTOs; never re-declares a type; renders unknown/    │
│   degraded states verbatim, never fabricates a "green".       │
└───────────────▲──────────────────────────────────────────────┘
                │ Tauri IPC (JS ⇄ Rust), serde/CBOR DTOs unchanged
┌───────────────┴──────────────────────────────────────────────┐
│  ssk-tauri-bridge   [NEW]   — the GUI backend (safe Rust)     │  unprivileged
│   • #[tauri::command] wrappers, no logic of their own         │
│   • IN-PROCESS reuse (no IPC): SystemPipeline::evaluate on     │
│     fixtures, KillSwitch/ServiceHost READ + audit verify,      │
│     AuditLedger::verify_against_head, PolicyEngine/Route plan, │
│     winhost pure connection-table parsers                     │
│   • PRIVILEGED verbs: forwarded over the named pipe below      │
│   • #![forbid(unsafe_code)] — unsafe stays only in ssk-winhost │
└───────────────▲──────────────────────────────────────────────┘
                │ ssk-ipc over Windows named pipe, CBOR framing,
                │ client-SID authenticated  [NEW auth; transport EXISTS]
┌───────────────┴──────────────────────────────────────────────┐
│  ssk-netd-helper   [NEW]    — the privileged broker           │  ELEVATED (SYSTEM)
│   • the ONLY component that runs elevated                     │
│   • routes each privileged verb through                       │
│     ssk-service-host::ServiceHost (AuthorizationManifest +     │
│     hash-chained audit) before touching the OS                │
│   • drives ssk-winhost: WindowsFirewallEnforcer (kill-switch),│
│     WindowsServiceHelper (SCM), WindowsConnectionSource (live) │
└──────────────────────────────────────────────────────────────┘
```

**Why this split:** the GUI runs unprivileged; only `ssk-netd-helper` is elevated. The privileged
verbs cross a process boundary (named pipe) so the unprivileged GUI never holds SYSTEM rights. The
*unprivileged* surface is genuinely large and needs no pipe at all — it links the pure controllers
directly (the whole point of choosing a Rust backend).

---

## 3. Command surface (grounded in real symbols)

`T` = transport. **IP** = in-process (bridge links the crate, no pipe). **PIPE** = forwarded to
`ssk-netd-helper` over the authenticated named pipe. `E` = requires elevation.

| GUI action | Rust symbol | Crate | T | E |
|---|---|---|---|---|
| System verdict on a fixture | `ssk_system::SystemPipeline::evaluate` → `SystemVerdict` | ssk-system | IP | – |
| Verify emission ledger | `SystemPipeline::verify_ledger`, `crown_head` | ssk-system | IP | – |
| Kill-switch state / audit | `ssk_boundary::KillSwitch::{state, audit_entries, verify_audit}` | ssk-boundary | IP | – |
| Read forensic ledger + verify | `ssk_netadmin::audit::AuditLedger::{entries, verify, verify_against_head}` | ssk-netadmin | IP | – |
| Durable audit sink load (torn-tail report) | `ssk_audit_store::FileAuditStore::load` → `LoadReport` | ssk-audit-store | IP | – |
| Classify flow / plan route (no execution) | `ssk_netadmin::{PolicyEngine::evaluate, RouteOrchestrator::plan}` | ssk-netadmin | IP | – |
| Parse connection table rows → surfaces | `ssk_winhost::connections::{parse_tcp_table, parse_udp_table, flow_to_traffic_window}` | ssk-winhost | IP | – |
| Daemon status / profiles / events (if daemon running) | `ssk_ipc::Request::{GetStatus, ListProfiles, SubscribeEvents}` | ssk-ipc | PIPE¹ | – |
| **Engage kill-switch** | `ssk_winhost::WindowsFirewallEnforcer::engage` → `EnforcementReceipt` (via `ServiceHost`) | ssk-winhost | PIPE | ✔ |
| **Release kill-switch** | `WindowsFirewallEnforcer::release(&EnforcementReceipt)` | ssk-winhost | PIPE | ✔ |
| **List live connections** | `ssk_winhost::WindowsConnectionSource::windows` → `Vec<TrafficWindow>` | ssk-winhost | PIPE | ✔ |
| **Install / start / stop / uninstall service** | `ssk_winhost::WindowsServiceHelper::{install,start,stop,uninstall}` (via `ServiceHost`) | ssk-winhost | PIPE | ✔ |

¹ The daemon quartet already speaks `ssk-ipc`; the bridge can reach a running `sskd` over the same
pipe. Elevation is not required for these — only the winhost verbs are.

**[NEW] `ssk-ipc::Request` variants to add** (the current enum — `GetStatus`, `ActivateProfile`,
`Deactivate`, `ListProfiles`, `InspectFlow`, `TraceRoute`, `ListRecentFlows`, `GetAuditEntries`,
`VerifyAuditChain`, `RunDoctor`, `ExplainError`, `SubscribeEvents` — has **no** privileged verbs):
`EngageKillSwitch`, `ReleaseKillSwitch(receipt)`, `ListConnections`, `InstallService`,
`StartService`, `StopService`, `UninstallService`, each with a matching `Response`. These are
additive; every DTO stays defined once in `ssk-ipc` and is consumed unchanged by the frontend.

---

## 4. The long pole — the privileged seam (do this first)

The framework choice is *not* the risk; this is. Two facts from the tree:

- **[EXISTS]** the Windows named-pipe transport: `ssk_ipc::server::serve_named_pipe`
  (`crates/ssk-ipc/src/server.rs:177`, `windows_transport` module).
- **[GAP, documented]** client-SID verification is **not** implemented:
  `ssk_ipc::auth::windows::CLIENT_SID_CHECK_IMPLEMENTED = false`
  (`crates/ssk-ipc/src/auth.rs:49-59`). Today the pipe's default DACL (same desktop session) is the
  only enforcement on Windows — explicitly *not* equivalent to the Unix peer-credential check.

For a channel that carries a **privileged kill-switch verb**, that gap is a fail-closed blocker.
The privileged seam work, in order:

1. **Close the client-SID gap.** Add `windows-sys`, implement client-SID verification on the
   named-pipe server (`GetNamedPipeClientProcessId` → open process token → compare SID against an
   allow-list), flip `CLIENT_SID_CHECK_IMPLEMENTED` to a real check. Fail closed if unknown.
2. **Set an explicit pipe DACL** granting only the intended SID(s) (and, if ever packaged, the
   package SID) — not the default DACL.
3. **Route every privileged verb through `ssk_service_host::ServiceHost`** so it inherits the
   `AuthorizationManifest` gate + hash-chained audit the current CLI path bypasses. The broker does
   no privileged work itself except via the injected `PrivilegedHelper`/`BoundaryEnforcer` traits —
   the same seam the pure crates already use.
4. **Coordinate the receipt store.** Kill-switch engage/release and service install/uninstall are
   receipt-based (`EnforcementReceipt`, `InstallReceipt`) with prior-existed semantics; the broker
   owns the `%TEMP%\ssk-winhost` receipt store and the `KILLSWITCH_ALREADY_ENGAGED` guard so a
   double-engage never orphans a rule.

**Vertical slice (proof of the seam):** `GetStatus` + exactly one privileged verb (kill-switch
engage/release), end-to-end over the SID-authenticated pipe through `ServiceHost`, with the audit
chain verifiable afterward. Everything else is additive once this holds.

---

## 5. Frontend

- **Framework-free** vanilla HTML/CSS/JS (keeps the JS supply chain minimal — a governance point
  raised in the stack review; revisit only if UI complexity demands a framework).
- Consumes `ssk-ipc` DTOs **as-is** over Tauri IPC. No type is re-declared on the JS side; the DTO
  is the single source of truth (this is exactly what a C# GUI could *not* have given us).
- Views (v1): kill-switch panel (state + engage/release with confirm), system-verdict card, audit
  ledger table + verify button, connections table, route/flow inspector.
- Accessibility: WebView2 gives a mature a11y tree; every control carries an explicit label/role;
  the kill-switch state is announced (a mis-read state is a safety issue — §7).

---

## 6. Crate layout

```
crates/
  ssk-tauri-bridge/     [NEW] Tauri backend: #[tauri::command] over IP reuse + PIPE forwarding
    src-tauri/          Tauri app (bundler config, capabilities)
    ui/                 framework-free frontend assets
  ssk-netd-helper/      [NEW] elevated broker: named-pipe server + ServiceHost routing
crates/ssk-ipc/         [MODIFY] add privileged Request/Response variants + client-SID auth
```

`#![forbid(unsafe_code)]` holds in both new crates; all unsafe stays quarantined in `ssk-winhost`
exactly as today. `windows-sys` (for the SID check) enters only `ssk-ipc` behind `#[cfg(windows)]`.

---

## 7. Fail-closed & no-overclaim rules (normative)

1. **Never fabricate a green.** If the daemon/broker is unreachable, a verdict is unknown, or a
   ledger fails to verify, the GUI renders that state verbatim (`Unknown`/`Degraded`/`Unverified`),
   never a default "ok". The existing daemon-absent path already models this (clear exit, no
   silent success) — the GUI mirrors it.
2. **Kill-switch truth.** The displayed kill-switch state is read from `KillSwitch::state` /
   broker, never cached optimistically. A confirmed engage shows engaged only after the receipt
   returns; a failed engage shows failed, not pending-forever.
3. **Single source of truth for DTOs.** No hand-mirrored types on any boundary. The bridge returns
   `ssk-ipc` serde types; the frontend renders them.
4. **Audit is verifiable in-panel.** The ledger view exposes `verify` / `verify_against_head` so a
   truncated or tampered chain is visible to the operator, not smoothed over.
5. **Privileged verbs are audited.** Every kill-switch/service action goes through `ServiceHost`'s
   hash-chained audit; the panel can show the resulting audit entry.

---

## 8. Packaging, signing, distribution

- **Bundle:** Tauri v2 bundler → signed **MSI/NSIS** (native path). MSIX intentionally deferred.
- **Signing:** Authenticode via `signtool`/`osslsigncode`, or Azure Trusted Signing (cloud HSM,
  CI-driven) — fitting the commit-signed enterprise ethos.
- **Runtime dependency:** WebView2 (evergreen; present on modern Win11, bootstrapper otherwise) —
  stated honestly as an end-user prerequisite.
- **Auto-update:** deferred to a later phase (signature-validated, rollback-capable per the
  roadmap) — not in v1.

---

## 9. Testing & verification boundary

- **Linux CI (existing lane):** all `ssk-tauri-bridge` in-process commands are unit/integration
  tested over fixtures (SystemPipeline verdicts, audit verify, connection-table parsing, route
  planning) — no Windows host needed. The DTO round-trip (serde/CBOR) is contract-tested.
- **Windows runner:** the named-pipe client-SID auth, the privileged verbs (kill-switch, service
  lifecycle), and the final signed bundle need a Windows job. The pure winhost parsers/receipt
  logic already test on Linux; the FFI/SCM/firewall calls are the Windows-only surface.
- **Operator step (honest boundary, as in `RUNBOOK_WINDOWS.md`):** final validation — real
  elevation, real firewall mutation, real SCM install — is the operator's step on a Windows 11
  admin box. This spec does not claim that is exercised in CI.
- **Frontend a11y:** validated on a real Windows host with a screen reader before any a11y claim.

---

## 10. Build phases (recommended order)

- **P0 — Privileged seam (long pole).** Close the client-SID gap + pipe DACL; route one verb
  (kill-switch engage/release) through `ServiceHost`; prove the vertical slice (§4).
- **P1 — Read-only panel.** `ssk-tauri-bridge` scaffold + in-process views: system verdict, audit
  ledger + verify, connections (parsed), route/flow inspector. No privileged calls. Fully
  Linux-CI-testable.
- **P2 — Privileged controls.** Wire kill-switch engage/release and service lifecycle through the
  P0 pipe; add the new `ssk-ipc` variants; audit-entry display.
- **P3 — Live capture & events.** `WindowsConnectionSource` live table over the pipe;
  `SubscribeEvents` stream to the panel.
- **P4 — Packaging & signing.** MSI/NSIS bundle, Authenticode, WebView2 bootstrap; (auto-update
  later).

Each phase ends green (build + fmt + clippy `-D warnings` + tests) and is committed separately,
consistent with the rest of this repo.

---

## 11. Open questions deferred to implementation (not blockers for approving this spec)

- Broker delivery: a dedicated elevated service vs. a UAC-`runas` helper spawned on demand — P0
  decides based on the client-SID slice.
- Allow-list policy for client SIDs (which principals may drive the privileged verbs).
- Whether the bridge ever needs the running `sskd` daemon, or only the winhost broker (affects
  whether the daemon quartet is surfaced in v1).
