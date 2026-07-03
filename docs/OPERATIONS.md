# Operations

## Local Run

```bash
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

## CI matrix

- fmt + clippy
- workspace build/test
- property smoke (`PROPTEST_CASES=32`)
- replay integration test
- cargo-audit
- no_std core/types check
