# Security Policy

## Adamant-Grade Security Baseline

ScorpioSync Kaleidoscorp Ω operates under an **Adamant-Grade** security posture.
Every layer of the system is fail-closed by design: on any uncertainty the system
denies, quarantines, and records forensically rather than silently allowing.

### Core Principles

| Principle | Implementation |
|-----------|---------------|
| **Fail-closed** | Gate vector, policy engine, and config all default to `fail_closed = true`. No rule match → deny. |
| **No unsafe code** | `#![forbid(unsafe_code)]` enforced workspace-wide. |
| **Deterministic execution** | All pipeline runs are replay-verifiable via hash-chained manifests. |
| **Immutable audit trail** | Session and forensic ledgers are Blake3 hash-chained; tampering is detectable. |
| **Strict attestation** | Interop handshakes verify capability attestations before accepting peers. |
| **Least privilege** | Operator profiles constrain adapters and risk levels per tenant. |
| **Supply-chain hygiene** | GitHub Actions are pinned to commit SHAs; `cargo audit` and `cargo deny` run in CI. |

## Reporting a Vulnerability

**Please do not open a public issue for security vulnerabilities.**

Report vulnerabilities privately via
[GitHub Security Advisories](https://github.com/LashSesh/kaleidoscorp.io/security/advisories/new).

Include:
- A clear description of the vulnerability
- Steps to reproduce
- Affected crates / versions
- Potential impact assessment

We aim to acknowledge reports within **48 hours** and issue a fix within **14 days**
for confirmed critical findings.

## Supported Versions

Only the latest commit on `main` is actively supported.
Security fixes are not back-ported to older releases.

## Secrets & Credentials

- **Never commit secrets** to this repository.
- Use environment variables for all integration credentials.
- `.env.example` lists placeholder names only — it contains no real values.
- The `Blake3KeyedVerifier` and `AttestationBinder` zero-key constructors are
  compile-time restricted to test builds.  Production deployments **must** supply
  a secret key sourced from a secret manager (e.g. `SSK_KMS_ENDPOINT`).

## Dependency Security

- [`cargo audit`](https://rustsec.org/) runs in CI and denies all advisories.
- [`cargo deny`](https://embarkstudios.github.io/cargo-deny/) enforces license
  allow-list, bans wildcard dependencies, and restricts sources to crates.io.
- [Dependabot](../.github/dependabot.yml) opens automated PRs for Cargo and
  GitHub Actions updates on a weekly schedule.

## Clock Skew Enforcement

The deterministic clock skew window is enforced to **≤ 300 seconds** by default.
Peers presenting a `deterministic_clock_epoch` outside this window are rejected
during the interop handshake.

## Chaos Drills

The `ssk-faultscan` crate exercises the full fault playbook on every CI run:

| Fault | Expected detection |
|-------|--------------------|
| `SignatureCorruption` | Core gate rejects |
| `CapabilityWithdrawal` | Capability gate rejects |
| `TtlExpiry` | Dissolution gate rejects |
| `AttestationFailure` | Capability + Core gates reject |
| `ReplayDrift` | Runtime replay manifest diverges |
| `LocatorUntrust` | Locator gate rejects |
