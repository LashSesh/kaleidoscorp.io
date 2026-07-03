# ScorpioSync-Kaleidoscorp Ω (Pure Rust Runtime)

Production-oriented core runtime implementation for the ScorpioSync-Kaleidoscorp Ω master specification.

## Quickstart

```bash
cargo build --workspace
cargo test --workspace
cargo run -p ssk-cli -- doctor
cargo run -p ssk-cli -- run --valid-fixture true
cargo run -p ssk-cli -- replay-verify --valid-fixture true
```

## User Journey
1. **Install/Build**: `cargo build --workspace`
2. **Health checks**: `cargo run -p ssk-cli -- doctor`
3. **Run**: `cargo run -p ssk-cli -- run --valid-fixture true`
4. **Verify deterministic replay**: `cargo run -p ssk-cli -- replay-verify --valid-fixture true`
5. **Verify ledger integrity**: `cargo run -p ssk-cli -- verify-ledger --path <ledger.json>`

All operational commands support `--json` for automation.

## Features
- Deterministic scheduler and replay-ready runtime pipeline
- BCIK crossing + fail-closed 12-gate vector
- Stitch tensor with hash-chained memory and file-ledger backends
- Canonical CBOR hashing (default BLAKE3; SHA-256 mapping available)
- Versioned interoperability layer (`ssk-interop`) with strict decode guards
- CLI commands: `doctor`, `run`, `replay-verify`, `verify-ledger`, `explain`, `config lint`, `config schema`
- Versioned fail-closed config model with migration baseline and schema export

## Development

### Build

```bash
cargo build --workspace
```

### Test

```bash
cargo test --workspace
PROPTEST_CASES=32 cargo test --workspace
```

### Replay Verification

```bash
cargo run -p ssk-cli -- replay-verify --valid-fixture true
```

## Release
- Semantic versioning
- Conventional commits recommended
- GitHub Actions release workflow packages binaries and crate source archive

See `/docs/ARCHITECTURE.md`, `/docs/OPERATIONS.md`, `/docs/INTEROP_SPEC.md`, `/docs/RUNBOOK.md`, and `/docs/EVOLUTION_STAGE_2_REPORT.md`.
