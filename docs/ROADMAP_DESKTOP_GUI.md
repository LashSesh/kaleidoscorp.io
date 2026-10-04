# Desktop GUI Roadmap (Post-Core)

Current implementation boundary (2026-09-24):
[modular UI and versioned read contract](MODULAR_DESKTOP_UI.md).
The standalone browser preview and a Windows Tauri host are runnable. The host
reads real daemon status; see [backend connection](DESKTOP_BACKEND_CONNECTION.md).
Verified protection observations, distribution and the proposed write APIs below
remain pending.

Recommended stack: **Tauri**.

## Scope

- Runtime control panel (start run, replay verify, ledger verify)
- Residue and gate-report viewer
- Determinism/replay diff inspector

## API surface

- `POST /run`
- `POST /replay-verify`
- `POST /verify-ledger`
- `GET /trace/:run_id`

## Packaging

- Tauri bundle for macOS/Windows/Linux
- Signed updates via Tauri updater
- Release channel separation: `stable`, `beta`

## Auto-update

- Check on launch (opt-in)
- Signature validation mandatory
- Rollback option to last known-good build
