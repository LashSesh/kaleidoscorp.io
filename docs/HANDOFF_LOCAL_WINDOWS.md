# Handoff — continuing the desktop GUI on a local Windows 11 machine

This file exists so a fresh Claude Code session running **locally on Windows** can pick up the
desktop-GUI work without re-deriving context. Everything below is verified against the tree, not
recalled.

## 1. Where things stand

The Tauri desktop GUI is specified in `docs/SPEC_TAURI_GUI.md` (revision 2 — read §0, §2–§8, §12,
§13 first). Phases **P0, P1 and P2 are implemented, tested and merged into `main`**:

| Phase | Crate / area | State |
|---|---|---|
| P0 — privileged broker core | `crates/ssk-netd-helper` | ✅ done — 12 tests |
| P1 — read-only panel (4 views + state machine + frontend) | `crates/ssk-tauri-bridge`, `ui/` | ✅ done — 20 tests |
| P2 — privileged control layer | `crates/ssk-tauri-bridge/src/control.rs` | ✅ done — 5 tests |
| P0 transport — named-pipe **client-SID** auth | `crates/ssk-ipc/src/auth.rs` | ⏳ **open — needs Windows** |
| P2 glue — `#[tauri::command]` + WebView2 window | `crates/ssk-tauri-bridge/ui/INTEGRATION.md` | ⏳ **open — needs a webview** |
| P3 — live Windows connection capture + events | `crates/ssk-winhost/src/connections.rs` | ⏳ **open — needs Windows** |
| P4 — MSI/NSIS packaging + Authenticode signing | — | ⏳ **open — needs Windows + signing cert** |

These were built in a Linux sandbox, which is exactly why the remaining phases are open: they need
real Windows APIs, a WebView2 runtime, and a signing identity. Nothing about them is "hard" — they
were deliberately not faked.

## 2. The rules that carry over (non-negotiable)

This codebase's whole value is that its claims are true. Keep these:

1. **Never overclaim.** If something is not executed and tested, say so. `cargo check` for a
   `#[cfg(windows)]` path is a *compile* check, not proof it works. Real elevation, real firewall
   mutation and real SCM installs are validated by the operator on a real admin box — see
   `RUNBOOK_WINDOWS.md`.
2. **Fail closed.** Unknown state renders as unknown/degraded, never as a green "ok". On the panel,
   a "protected" affordance binds **only** to `protection_confirmed` (engaged ∧ OS rule present ∧
   consistent), never to `journal_claims_engaged`. An alarm always dominates.
3. **`#![forbid(unsafe_code)]` holds everywhere except `ssk-winhost`**, which is the single
   quarantine for FFI. New Windows FFI (e.g. the client-SID check) belongs **there**, not in
   `ssk-ipc` or the bridge.
4. **Evidence preflight before implementing.** Re-run the symbol check in `SPEC_TAURI_GUI.md` §0
   (`rg` each `[EXISTS]` symbol) and abort if one no longer resolves.
5. **Every phase ends green and is committed separately** (build + fmt + clippy `-D warnings` +
   tests).

## 3. The local green gate

Mirror CI (`.github/workflows/ci.yml`). All four must pass:

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo build --workspace --all-targets
cargo test --workspace
```

Baseline at the time of this handoff: **114 test groups green**, clippy clean. If the count drops or
clippy complains, something regressed — fix it before adding scope.

The Windows-only surface additionally:

```powershell
cargo build -p ssk-winhost -p ssk-cli
cargo clippy -p ssk-winhost --all-targets -- -D warnings
cargo test -p ssk-winhost            # 47 tests; the pure parsers run everywhere
```

## 4. Recommended order for the remaining work

**P0-transport first — it is the long pole and it gates everything privileged.**

1. **Close the client-SID gap.** `crates/ssk-ipc/src/auth.rs:49-59` documents it:
   `CLIENT_SID_CHECK_IMPLEMENTED = false`, and today only the pipe's default DACL protects it —
   explicitly *not* equivalent to the Unix peer-credential check. Implement
   `GetNamedPipeClientProcessId` → open process token → compare SID against an allow-list, in
   `ssk-winhost` (the unsafe quarantine), exposed as a safe function `ssk-ipc` calls. Fail closed on
   any error. Set an explicit pipe DACL rather than the default. Then flip the flag and delete the
   "documented gap" wording — but only once a real test exercises it.
2. **Wire the broker over the pipe.** `ssk-netd-helper` is transport-agnostic on purpose: its
   `Broker::handle(CommandEnvelope) -> BrokerResponse` is synchronous and pure. The pipe server
   decodes a frame with `ssk_netd_helper::decode_envelope` and calls `handle`. On the client side,
   implement `ssk_tauri_bridge::control::ControlClient` over the pipe (the in-process impl in
   `crates/ssk-tauri-bridge/tests/control.rs` is the reference). Supply a **CSPRNG** `NonceSource`
   in production — the test one is deliberately sequential.
3. **P2 glue / webview.** Follow `crates/ssk-tauri-bridge/ui/INTEGRATION.md` verbatim: optional
   `tauri` feature, `build.rs` gated on `CARGO_FEATURE_TAURI`, `[[bin]]` with
   `required-features = ["tauri"]` so the default workspace build never links `wry`. Keep the strict
   CSP from `ui/index.html`, disable devtools in release, lock navigation, expose only the specific
   commands. The commands hold **no logic** — they delegate to `view::*` / `control::*`.
4. **P3 live capture.** `platform_capture_flows` is private and only yields `Vec<TrafficWindow>`,
   which **drops the PID**. Add a public `capture_flows() -> Vec<FlowRow>` to `ssk-winhost` so the
   panel can show PID-bearing rows without re-implementing the IP Helper two-call. The pure parsers
   (`parse_tcp_table` / `parse_udp_table`) already exist and are tested — reuse them.
5. **P4 packaging.** Tauri bundler → signed MSI/NSIS, Authenticode via `signtool` or Azure Trusted
   Signing. MSIX is deliberately *not* v1 (see the stack decision in §1 of the spec).

## 5. Useful landmarks

- `docs/SPEC_TAURI_GUI.md` — the authoritative spec (topology, protocol, fail-closed rules, status).
- `docs/IMRT_IMPLEMENTATION_SPEC.md` — the theory-conformance spec; §5a logs 25 closed gaps.
- `RUNBOOK_WINDOWS.md` — operator steps for the existing winhost backends.
- `crates/ssk-netd-helper/tests/p0_broker.rs` — the reference for how a privileged verb is driven.
- `crates/ssk-tauri-bridge/tests/view_core.rs` — the fail-closed guarantees, in test form.
- Regenerate golden fixtures after a DTO change:
  `cargo test -p ssk-tauri-bridge write_goldens -- --ignored`, then commit `tests/fixtures/*.json`.
