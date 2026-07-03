# ScorpioSync-Kaleidoscorp Ω (Pure Rust Runtime)

Production-oriented core runtime implementation for the ScorpioSync-Kaleidoscorp Ω master specification.

## Quickstart

```bash
cargo build --workspace
cargo test --workspace
cargo run -p ssk-cli -- run --valid-fixture true
```

## Features

- Deterministic scheduler and replay-ready runtime pipeline
- BCIK crossing + fail-closed 12-gate vector
- Stitch tensor with hash-chained memory and file-ledger backends
- Canonical CBOR hashing (default BLAKE3; SHA-256 mapping available)
- CLI commands: `run`, `replay-verify`, `verify-ledger`

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

### Run replay verification

```bash
cargo run -p ssk-cli -- replay-verify --valid-fixture true
```

## Release

- Semantic versioning
- Conventional commits recommended
- GitHub Actions release workflow packages binaries and crate source archive

See `/docs/ARCHITECTURE.md`, `/docs/OPERATIONS.md`, and `/docs/COMPLETION_CHECKLIST.md`.
