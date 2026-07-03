# Operations

## Local Run

```bash
cargo run -p ssk-cli -- doctor
cargo run -p ssk-cli -- run --valid-fixture true
```

## Replay Verification

```bash
cargo run -p ssk-cli -- replay-verify --valid-fixture true
```

## Ledger Verification

```bash
cargo run -p ssk-cli -- verify-ledger --path /tmp/ledger.json
```

## Config Validation / Schema

```bash
cargo run -p ssk-cli -- config lint --path ./ssk-config.yaml
cargo run -p ssk-cli -- config schema --json
```

## Explain Diagnostics

```bash
cargo run -p ssk-cli -- explain replay
cargo run -p ssk-cli -- explain Core
```

## CI Matrix
- fmt + clippy
- workspace build/test
- property smoke (`PROPTEST_CASES=32`)
- replay integration test
- interop golden/fuzz tests
- config schema/lint guard tests
- cargo-audit
- no_std core/types check
