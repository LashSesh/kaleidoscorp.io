# Desktop GUI Roadmap (Post-Core)

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
