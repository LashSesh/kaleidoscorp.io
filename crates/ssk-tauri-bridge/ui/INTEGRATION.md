# Tauri integration template (webview runner — NOT compiled by default CI)

This crate's default build is the **portable view core** (`src/view.rs`,
`src/dto.rs`, `src/state.rs`, `src/error.rs`): pure Rust that turns the SSK
security surfaces into JSON DTOs, fully tested on Linux CI. It deliberately does
**not** depend on `tauri` — the WebView2 window and the `#[tauri::command]` glue
need a `webkit2gtk`/`wry` runner that headless CI lacks, so wiring them is a
follow-up on a webview-equipped runner. This file is that wiring, kept as a
template so nothing here drags `wry`/`webkit2gtk` (or a large registry fetch)
into the default workspace build.

Honest boundary (SPEC_TAURI_GUI.md §12, verification): Linux CI proves the
projection logic + the JSON wire contract + the state machine. It does **not**
prove the webview, the `invoke` round-trip, `tauri_build::build()`, live Windows
capture (empty off-Windows), or the privileged seams. Those are deferred to a
webkit runner (glue type-check), a Windows runner (P3 live capture), and the
release pipeline (P4 packaging/signing).

## 1. Cargo wiring (behind an optional feature)

```toml
[features]
default = []
tauri = ["dep:tauri", "dep:tauri-build"]
ts    = ["dep:ts-rs"]            # TS type generation (pure Rust, Linux-OK, opt-in)

[dependencies]
tauri = { version = "2", optional = true, default-features = false, features = ["wry"] }
ts-rs = { version = "10", optional = true }

[build-dependencies]
tauri-build = { version = "2", optional = true }

[[bin]]
name = "ssk-desktop"
required-features = ["tauri"]   # skipped by `cargo build --all-targets` by default
```

`build.rs` (only runs the tauri codegen when the feature is on):

```rust
fn main() {
    if std::env::var("CARGO_FEATURE_TAURI").is_ok() {
        tauri_build::build();
    }
}
```

## 2. The command glue (`src/tauri_cmd.rs`, `#[cfg(feature = "tauri")]`)

The commands hold **no logic** — they read the injected source ports and
delegate to the pure `view::*` functions, returning the same DTOs CI already
tests. A snapshot is assembled fail-closed: any unreachable source degrades the
panel state rather than emitting a green.

```rust
#[cfg(feature = "tauri")]
mod tauri_cmd {
    use crate::{view, state::{classify, PanelState}, dto::*};

    // AppState carries the read ports (SPEC §12): the in-process broker handle
    // for GetStatus, KillSwitch::verify_audit for the audit view, and the
    // ConnectionsReader (WindowsConnectionSource on Windows, empty elsewhere).
    struct AppState { /* broker, audit_reader, connections_reader */ }

    #[tauri::command]
    fn get_panel_snapshot(state: tauri::State<AppState>) -> PanelSnapshotDto { /* ... */ }

    #[tauri::command]
    fn get_kill_switch_view(state: tauri::State<AppState>) -> KillSwitchViewDto { /* ... */ }

    pub fn run() {
        tauri::Builder::default()
            .invoke_handler(tauri::generate_handler![get_panel_snapshot, get_kill_switch_view])
            .run(tauri::generate_context!())
            .expect("run panel");
    }
}
```

`tauri.conf.json` must set the strict CSP from `ui/index.html`, disable
`devtools` in release, lock navigation to the bundled origin, and expose only
the specific commands above (no `shell`/`fs`/`http`, no
`dangerousRemoteDomainIpcAccess`).

## 3. TypeScript types (`--features ts`, Linux-OK, opt-in job)

`ts-rs` is pure Rust, so `cargo test -p ssk-tauri-bridge --features ts` can run
on Linux to regenerate `ui/src/generated/*.ts` from the DTOs, guarded by
`git diff --exit-code`. It is kept out of the default green so the default build
never needs any JS toolchain; the Rust-side wire strings tested in
`tests/view_core.rs` are the contract until that job runs.

## 4. Frontend contract

`ui/panel.js` renders strictly from the DTOs. The one safety rule: a
"protected/green" affordance binds **only** to `kill_switch.protection_confirmed`
(engaged ∧ OS rule present ∧ consistent), never to `journal_claims_engaged`; an
alarm (`is_alarm`) always dominates; an unknown/degraded panel is never green.
