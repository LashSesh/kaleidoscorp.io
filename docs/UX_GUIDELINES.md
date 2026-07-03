# CLI UX Guidelines

## Principles
- Fail closed by default.
- Every error includes machine code, class, exit code, and next steps.
- All operational commands support `--json`.

## User Journey
1. `ssk doctor`
2. `ssk config lint --path <config>`
3. `ssk run --valid-fixture true`
4. `ssk replay-verify --valid-fixture true`
5. `ssk verify-ledger --path <ledger.json>`

## Accessibility and Clarity
- Human output uses concise status markers and explicit follow-up action.
- JSON output keeps stable top-level fields (`status`, `next_steps`, payload).
- `ssk explain <error|gate>` provides both human and machine-focused diagnostics.
