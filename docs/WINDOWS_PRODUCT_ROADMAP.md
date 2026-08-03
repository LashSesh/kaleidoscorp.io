# Windows Product Roadmap

> **Status:** Written 2026-08-02, on the first run of this workspace on real Windows 11 hardware
> (de-DE, unelevated, rustc 1.95.0). Every status claim below was produced by *executing* something
> on that machine, not by reading a document. Where a claim could not be executed — anything behind
> the UAC boundary — it is marked as an assumption, not a finding.
>
> This document supersedes the forward-looking sections of `RELEASE_BLOCKER_REGISTER.md`,
> `PRODUCT_CONTRACT_MATRIX.md` and `NEXT_IMPLEMENTATION_RUN_SPEC.md`, all of which have drifted —
> in **both** directions (some gaps are closed, some "closed" items are not).

---

## 0. Why this document exists now

Every prior implementation pass ran in a Linux sandbox. That sandbox could not compile, run, or
observe any `#[cfg(windows)]` path, and the project honestly said so — `docs/SPEC_TAURI_GUI.md §13`
marks the named-pipe transport, live capture, and packaging as *"Deferred — Windows runner"* and
records an explicit *"operator validates on a real admin box"* boundary.

**That boundary has now been crossed for the first time.** This document is the result, and the
single most important thing it establishes is that the Linux-verified status was wrong in both
directions: capabilities believed unverified actually work, and capabilities marked "✅ Done" do not.

---

## 1. Measured status

### 1.1 The repo's own gates, on Windows

| Gate (as CI defines it) | Result on Windows 11 |
|---|---|
| `cargo build --workspace` | ✅ passes (43 s) |
| `cargo build --workspace --all-targets` | ❌ **does not compile** |
| `cargo test --workspace` | ❌ **does not compile** — no test runs at all |
| `cargo test --workspace --exclude ssk-daemon` | ⚠️ 535 passed / **12 failed** (see §1.2 — the true count is 13; one was masked) |
| `cargo clippy --workspace --all-targets -- -D warnings` | ❌ fails (`ptr_arg`, `ssk-winhost/src/service.rs:329` — fires on Linux too) |
| `cargo fmt --all -- --check` | ❌ fails on 152 files (CRLF vs. `rustfmt.toml`; no `.gitattributes`) |

The compile break is one line: `crates/ssk-daemon/tests/round_trip.rs:46` references
`ssk_ipc::client::UnixClient`, which is `#[cfg(unix)]`, with no guard on the test file.
One un-gated symbol makes the entire test suite unrunnable on the target platform.

### 1.2 The 13 failing tests

> **Corrected 2026-08-02 after P0.** This section originally said 12. It is **13**. The
> thirteenth — `ssk-daemon --lib supervisor::tests::run_doctor_reports_real_checks` — was
> *unobservable* at first measurement, because the `round_trip.rs` compile error prevented
> `ssk-daemon` from producing a test binary at all. It only became visible once P0 fixed the
> compile break. A masked failure is exactly the failure mode this document exists to catch, so it
> is recorded here rather than quietly corrected.

| Suite | Fails | Cause |
|---|---|---|
| `ssk-netd-helper --test p0_broker` | 8/12 | `store.rs:174` `assert_restrictive_dacl` runs `icacls /inheritance:r` granting only SYSTEM + Administrators — which revokes the *running* process's own access; the next `File::create` returns `os error 5`. **Root cause now confirmed — see §5.2.** Only 1 is a distinct defect; the other 7 are downstream of the failed `save()`. |
| `ssk-cli --test activate_real_egress` | 2 | Polls for a Unix socket path the daemon never binds on Windows. |
| `ssk-cli --test ipc_status_snapshot` | 1 | Same. |
| `ssk-daemon --lib` `run_doctor_reports_real_checks` | 1 | **Was masked by the compile error.** `supervisor.rs:256` opens `/dev/urandom` unconditionally, so the entropy check is `ok: false` on every Windows box and the assertion at `supervisor.rs:1013` fails. A duplicate of the CLI defect at `ssk-cli/src/main.rs:1828`. Owned by P2. |
| `ssk-core --test ui` | 1 | `trybuild` `.stderr` snapshots stale vs. rustc 1.95. Cosmetic. |

### 1.3 What actually works on Windows (verified by running it)

- **`ssk-netcore` is real.** Genuine TCP / SOCKS5 (RFC 1928/1929) / HTTP-CONNECT / rustls TLS / DNS
  handshakes, tested against live listeners.
- **The Windows named-pipe *server* works.** `sskd.exe` binds `\\.\pipe\kaleidoscorp-sskd`; an
  auditor drove it from a hand-written .NET client through the CBOR framing and got back a valid
  116-byte `Response::Status` DTO. **The repo's own "never compiled or tested" caveats
  (`ssk-ipc/src/server.rs:123-127`, `README.md:114`) are stale in the pessimistic direction.**
- **Live flow capture is real.** `ssk winhost capture` returned 45–72 real IPv4 flows with real
  remote endpoints, unelevated, via IP Helper.
- **The SCM path is real.** `winhost service install` uses the `windows-service` crate and returns a
  true Win32 access-denied when unelevated.
- **The deterministic core is real and well-tested.** 535 green tests, real property tests,
  `unsafe_code = "forbid"` workspace-wide.

### 1.4 What did not work on Windows

> **All five items below were fixed by P2 (2026-08-02) and disproved live by an independent verifier.**
> They are kept, not deleted, because this section is the measured baseline the whole plan was derived
> from — striking it would erase the evidence that the work was needed. See §P2's status block for the
> verbatim output of the real binaries doing each of these things.

- **The entire control plane is dead.** There is **no named-pipe client anywhere in the tree**
  (zero occurrences of `NamedPipeClient`/`ClientOptions`). `ssk-cli/src/main.rs:401-411` is a
  hardcoded `#[cfg(not(unix))]` stub. Verified live: `ssk status` returns
  `error(Runtime/12): daemon-backed commands use a Unix domain socket` **while the daemon is
  running and its pipe is bound**. The server half is done; the client half was never written.
- **The kill-switch cannot engage on non-English Windows.** `firewall.rs:243` matches the English
  literal `"No rules match the specified criteria"`. On this de-DE machine netsh prints
  `"Keine Regeln stimmen mit den angegebenen Kriterien überein."`, so `parse_show_output` falls
  through to `Err(NonZeroExit)` and `engage_with` aborts **before ever adding a rule**. Reproduced:
  `ssk --json winhost killswitch engage` → `KILLSWITCH_ENGAGE_FAILED`. The emitted next-step
  ("requires Administrator") is misleading — elevation is not the problem.
- **`ssk doctor` always fails.** `main.rs:1826` opens `/dev/urandom` unconditionally → exit 16 on
  every Windows machine, every other check passing. Duplicated in `supervisor.rs:255`, so the IPC
  `RunDoctor` DTO is poisoned too.
- **`ssk --version` errors out.** No `version` attribute on the clap derive.
- **Only one daemon instance can ever exist.** `paths.rs:24` returns a fixed global pipe name while
  the Unix socket is per-`$SSK_STATE_DIR`. A second instance dies with `os error 5`.

### 1.5 Reachability

44 crates, ~43.5k LOC of `src`. Roughly **29% (~12.8k LOC) links into no shipped binary at all.**
The privileged broker `ssk-netd-helper` — the entire P0 security core — is constructed in exactly
two places workspace-wide, **both test files**. It declares no `[[bin]]` and no transport. The
`ssk-tauri-bridge` crate has zero consumers in either direction.

---

## 2. Security findings — fix before any distribution

These are the reason this roadmap does not start with a GUI or an installer. Both were confirmed by
reading the code directly.

### SEC-1 — Forged rollback receipt drives an elevated `netsh delete rule` (Critical)

`ssk-cli/src/main.rs:963-976` reads `%TEMP%\ssk-winhost\killswitch-<hash>.json`,
`serde_json::from_slice` it, and hands it **straight** to `enforcer.release(&receipt)`. The Blake3
`receipt_id` is computed at construction (`ssk-boundary/src/lib.rs:93-122`) and **never recomputed
on load**. `firewall.rs:389-395` `rule_from_prior_state` then takes the rule name verbatim from the
`prior_state` string, filtering only for non-empty — no prefix check, no shape validation.

An auditor planted a receipt with an all-zero `receipt_id` and an arbitrary rule name and drove it
to netsh; it was stopped only by the elevation boundary. `%TEMP%` is user-writable and
auto-cleaned, so this is simultaneously a **local privilege-escalation vector** and a
**denial-of-rollback**: lose the receipt and the machine stays severed with no recovery path.

**Fix:** recompute and verify `receipt_id` on load; validate rule names against the
`SSK-KillSwitch-` prefix and shape; move receipts from `%TEMP%` to `%ProgramData%\ScorpioSync\state`
(the path `store.rs:75-82` already defines) with a correct ACL; add a receipt-less recovery path
that reconciles against the observed OS rule.

### SEC-2 — Documented install procedure hands SYSTEM to a user-writable binary (Critical)

`ssk-winhost/src/service.rs:192-224` creates the service with `account_name: None` (= LocalSystem)
and `executable_path: exe_path.to_path_buf()` — **no check that the target lives in a protected
directory, no ACL check, no signature check.** `RUNBOOK_WINDOWS.md:101-103` then instructs exactly
`--exe .\target\release\ssk-svc.exe`, inside the user-writable build tree.

Any unprivileged process owned by that user can overwrite the binary and obtain SYSTEM on next
start. This is a textbook elevation-of-privilege, and any future installer would inherit it.

**Fix:** refuse to install a LocalSystem service whose image path is user-writable — check the
target directory's ACL (ideally its Authenticode signature) before `create_service`. Correct the
runbook.

### SEC-3 — The Windows IPC surface is unauthenticated (High) — **CLOSED by P2**

> **Resolved 2026-08-02.** The constant is deleted, `ImpersonateNamedPipeClient`-based peer
> authentication is implemented in `ssk-winhost` and injected at `sskd`'s composition root, and the
> pipe now carries an explicit DACL. Closure was proven by **mutation**, not by a passing test: a
> permissive authenticator makes the anonymous-impersonation test fail with *"the peer check is not on
> the served path"*. The description below is the measured baseline and is kept as evidence.
>
> Two things it got slightly wrong, both discovered while fixing it: the exposure was worse than
> "only the default DACL applies" (Everyone **and** ANONYMOUS LOGON held read; the same user held
> `FILE_CREATE_PIPE_INSTANCE`, i.e. squatting), and same-user access remains — by design — so the
> attacker set narrowed rather than vanished. Same-user squatting closes in P3.

`ssk-ipc/src/auth.rs:56-60` is `pub const CLIENT_SID_CHECK_IMPLEMENTED: bool = false` — a constant,
not code. `server.rs:160-173` performs **no peer check at all**, where its Unix twin calls
`check_peer_same_user` at `server.rs:107`. The pipe is created with no `SECURITY_ATTRIBUTES`
(`server.rs:142-145`), so only the default DACL applies.

Two auditors independently drove privileged verbs from unrelated, unelevated PowerShell processes
with zero credentials. One activated a **nonexistent profile** (`totally-made-up-profile`) and
received `Protected` plus a hash-chained audit entry — the ledger will cryptographically attest to
protection that never existed.

This is tolerable only because the daemon is currently unprivileged. It becomes a live EoP the
moment the broker is hosted as SYSTEM (phase P3), which is why P2 must precede P3.

---

## 3. Three structural findings

**(a) There is no traffic ingress — the product promise is unimplemented.**
No proxy listener, no WFP/WinDivert/LSP/TUN hook, no PAC, no proxy-settings writer. `ssk-capture`
has no OS capture; its only production `TrafficSource` is a hardcoded CLI fixture. `activate`
requires an operator-typed `--dest`, opens exactly one TCP connection, and **writes zero bytes
through it** — `EgressSession::transport_mut` (`ssk-netcore/src/session.rs:63`) has zero callers of
any kind. The supervisor hardcodes `RiskLevel::Low`/`ProtocolKind::Tcp`, so every non-Direct
executor is structurally unreachable. "Proxifier replacement" today means: a dialer with a planner
bolted on.

**(b) Several fail-closed gates cannot fail.**
`ssk-stitch` (23 LOC) is the only production `StitchCandidate` producer and hardcodes
`seam_ok`/`boundary_complete`/`replay_ready`/`focus_ready = true`, unconditionally satisfying ~9
predicates across the advertised 12-gate vector. `ssk-cli/src/main.rs:665-666` hardcodes
`parallax_consistent: true, replay_equal: true` — exactly what `ssk-system`'s own doc comment says a
caller with no evidence must **not** do. `ssk-system/src/lib.rs:145-148` builds `TargetProfile` from
the very signature it then compares against, so all 11 spectral dimensions are identically `0.0` by
construction and the most expensive component in the codebase has zero influence and zero coverage.
These are correctness defects in a fail-closed security system, not tuning issues.

**(c) CI is structurally incapable of catching any of this.**
13 of 14 jobs run `ubuntu-latest`. The single Windows job runs three commands scoped to 1 of 44
crates. `release.yml` builds `--release` on Linux, **discards the binaries, and tars the source.**
There is no `Cargo.lock` (gitignored), no toolchain pin, no MSRV, no `[profile.release]`, and no
`LICENSE` file despite `Cargo.toml:53` declaring Apache-2.0.

---

## 4. The plan

Ordering rationale: nothing can be *verified* until the gates run on Windows (P0); the privileged
layer must be *safe* before it is elevated or distributed (P1); it must be *reachable* before there
is anything to host or display (P2); and the GUI is deliberately last, because a panel built before
P2–P5 could only ever display a fabricated green — precisely the RB-A1 failure the project's own
blocker register exists to prevent.

### P0 — Make the truth measurable  ·  effort S–M

*Goal: get the repo's own gates green on Windows and pin what a build means.*

- cfg-gate `ssk-daemon/tests/round_trip.rs` so `--all-targets` and `cargo test --workspace` compile
- fix the `ptr_arg` lint at `ssk-winhost/src/service.rs:329`
- add `.gitattributes` (`* text=auto eol=lf`) and normalize, so `fmt --check` can pass
- commit `Cargo.lock`, remove it from `.gitignore:2`; add `rust-toolchain.toml`, `rust-version`
  (MSRV), an explicit `[profile.release]`; pin `cargo-audit`/`cargo-deny`
- **expand the Windows CI job to the full gate**: `build --all-targets`, `test --workspace`,
  `clippy -D warnings`, `fmt --check` on `windows-latest`, plus dedicated jobs for `ssk-ipc`,
  `ssk-daemon`, `ssk-netd-helper`, `ssk-tauri-bridge`
- re-bless `ssk-core/tests/ui/*.stderr`
- correct the doc overclaims — **including the two that are stale pessimistically** (the named-pipe
  server works)

**Exit:** on a clean Windows checkout, `build --all-targets`, `clippy -D warnings` and
`fmt --check` exit 0; `cargo test --workspace` **compiles and runs to completion**, with every
remaining failure enumerated against the phase that owns it; CI runs all four gates on
`windows-latest`; no doc asserts a capability contradicted by code.

> **Corrected 2026-08-02.** This exit criterion originally demanded that *all four* gates exit 0.
> That was a defect in this document: the same roadmap assigns the store DACL fix to P1 and the
> `/dev/urandom` fix to P2, so no amount of P0 work could ever have satisfied it. P0 owns making
> the test gate *runnable and honest*, not making it green — greenness is earned by P1 and P2.

**Status: DONE (2026-08-02), against the corrected criterion above.**

| Gate | Result |
|---|---|
| `cargo build --workspace --all-targets` | ✅ exit 0 (38 s, 44 crates, zero warnings) |
| `cargo clippy --workspace --all-targets -- -D warnings` | ✅ exit 0, zero diagnostics |
| `cargo fmt --all -- --check` | ✅ exit 0 (315 files `i/lf w/lf`, zero CRLF; `rustfmt.toml` unchanged) |
| `cargo test --workspace --no-fail-fast` | ⚠️ runs: 114 suites, **560 passed / 9 failed / 1 ignored** |

The 9 remaining failures are enumerated in §1.2: **8 owned by P1** (the store DACL — 1 distinct
defect plus 7 downstream) and **1 owned by P2** (the daemon's `/dev/urandom` doctor probe).
No test was `#[ignore]`d, no lint relaxed, no assertion deleted, and `rustfmt.toml` was not weakened
— an independent verification pass checked specifically for all four.

**One coverage loss to repay in P2.** `activate_real_egress.rs` and `ipc_status_snapshot.rs` were
`#![cfg(unix)]`-gated. Unlike `round_trip.rs` (which genuinely cannot compile on Windows), these two
*would* compile — they were failing at runtime because the CLI's Windows control plane is a
`DAEMON_UNIX_ONLY` stub. Gating them silences a red test that was reporting a real product defect.
The module docs state the mechanism and name P2, and no assertion was weakened, but the net effect
is that `cargo test` is now green on the CLI while the CLI's control plane is dead on Windows.
**P2 must add a Windows-side test asserting that stub is what you get**, so the gap is asserted
rather than merely absent — otherwise this loss becomes permanent and invisible.

> **Superseded 2026-08-02 — repaid better than asked.** P2 deleted the `DAEMON_UNIX_ONLY` stub
> outright and implemented the real named-pipe client, so "assert the stub is what you get" became
> unsatisfiable. Instead **all three gated files were un-gated and now run on Windows**
> (`activate_real_egress.rs`, `ipc_status_snapshot.rs`, `round_trip.rs`), contributing 5 executing
> tests where they contributed 0. A verifier diffed every assertion against the P0 state line by line:
> all originals survive **verbatim**, including the two load-bearing ones ("a real refused connection
> must report FailClosed, never Protected" and "127.0.0.1 is a literal IP, so no DNS lookup should
> have occurred") and `round_trip.rs`'s "audit chain must not be vacuously empty". Nothing was
> softened. The debt is closed.

**Expect two red CI jobs on the first run**, for real reasons that are already written down here:
`build_test (windows-latest)` and `windows_crate_gates (ssk-daemon)`. The `ssk-netd-helper` leg may
go *falsely green*, because GitHub's `windows-latest` runner is elevated — see §5.2.

### P1 — Stop the bleeding in the privileged layer  ·  effort M–L

*Goal: eliminate SEC-1, SEC-2 and the locale break. Must precede any distribution or elevation.*

- validate the rule-name prefix/shape before anything reaches netsh, and verify receipt integrity
  on load

  > **Corrected 2026-08-02.** This item originally read "recompute the Blake3 `receipt_id`" as
  > though that closed SEC-1. It does not. `EnforcementReceipt::receipt_id`
  > (`ssk-boundary/src/lib.rs:100-122`) is an **unkeyed** Blake3 hash over `{scope, prior_state}`,
  > so an attacker simply computes the matching hash for their own `prior_state`. Recomputation
  > catches corruption and naive tampering only.
  >
  > The controls that actually bound this, in order of value:
  > 1. **Rule-name validation** — even a perfectly forged receipt can then only name SSK's own
  >    kill-switch rules, never an arbitrary firewall rule. This holds regardless of file location
  >    or crypto, which is why it ranks first.
  > 2. **Storage location + DACL** — move receipts out of user-writable `%TEMP%` so an unprivileged
  >    process cannot plant one at all. This is the primary *preventive* control.
  > 3. **Digest recomputation** — cheap defense in depth; keep it, but do not mistake it for the fix.
  >
  > A keyed MAC was considered and is a judgement call, not an obvious win: the key would have to
  > live somewhere an unprivileged process cannot read, which is the same ACL problem one level down.
- move receipts from `%TEMP%` to `%ProgramData%\ScorpioSync\state` with a correct ACL
- add `winhost killswitch status` and a receipt-less recovery path reconciling against the OS rule;
  fix the silent-skip branch (`firewall.rs:519-527`) that reports "egress restored" without deleting
- **make netsh handling locale-independent**: delete the English string constants; ensure no branch
  reads command output at all; add a non-English CI leg

  > **Two corrections, both from measurement on the de-DE box (2026-08-02).**
  >
  > **(1) "Key rule presence on exit code" is unsound as written.** Measured: netsh returns exit **1**
  > for *no match*, *invalid value*, *wrong argument count* AND *unknown command* alike — the code
  > conflates them. But the signal is **asymmetric**, and that is what a fail-closed product needs:
  > **exit 0 ⟹ the rule exists** (no failure mode in the probe set produced 0); **exit 1 ⟹
  > indeterminate**. So exit code may confirm presence, never conclude absence. The implementation
  > follows that asymmetry.
  >
  > **(2) "Fix OEM-codepage decoding" rests on a premise that does not reproduce.** netsh emits
  > **UTF-8** on this box: `ü` is `c3 bc`, not CP850 `0x81` or CP1252 `0xFC`. Byte-identical under
  > `chcp 850`, `1252` and `65001`, and identical whether redirected to a file or a pipe. So
  > `String::from_utf8_lossy` was *already correct*, and "fixing" it to CP850 would have **broken**
  > it (`++berein`). The correct change was not a codepage at all: keep the raw bytes as `Vec<u8>`,
  > decode lossily only for human-readable diagnostics, and let no branch read the text — which
  > closes the encoding question by construction instead of by guessing at netsh's internals.
  >
  > `INetFwRules` COM was evaluated and **rejected with evidence**: `windows-sys` 0.59 generates no
  > COM interfaces at all (its firewall module is 281 lines with zero vtables — only the `NetFwPolicy2`
  > CLSID constant), so it would mean hand-writing IUnknown/IDispatch vtables, BSTR lifetimes and
  > manual AddRef/Release — a large unsafe surface that cannot be tested elevated here. That FFI
  > budget is better spent once, on WFP. `Get-NetFirewallRule` is locale-independent if you read
  > `FullyQualifiedErrorId` rather than `.Message`, but is ~31× slower (2112 ms vs 68 ms) and is
  > broken by Constrained Language Mode, AppLocker and Defender ASR — so it is used only for the
  > cold path (status / orphan enumeration / receipt-less recovery), as an optional capability that
  > degrades explicitly.
- refuse to install a LocalSystem service whose image path is user-writable; correct the runbook
- fix `store.rs:174-193` so the DACL grants the running principal, or applies the SYSTEM-only DACL
  only when elevated; make the store test-injectable; add an elevation preflight + typed
  `NOT_ELEVATED` error
- bind the broker's idempotency cache key to the command discriminant (`broker.rs:143-145`); bound
  `seen_nonces` with TTL/LRU; constant-time compare at `broker.rs:125`
- replace `AuthorizationManifest::is_valid_for`'s four non-empty-string checks
  (`ssk-signature/src/policy.rs:116-123`) with a real authorization decision

**Exit:** a forged receipt is rejected with a typed error and never reaches netsh. Engage **and**
release succeed on an elevated de-DE Windows 11 VM with a verified before/after `netsh` rule diff.
`cargo test -p ssk-netd-helper` passes on `windows-latest`.

**Status: CODE COMPLETE (2026-08-02). Elevated validation outstanding.**

| Gate | Result |
|---|---|
| `cargo build --workspace --all-targets` | ✅ exit 0 |
| `cargo clippy --workspace --all-targets -- -D warnings` | ✅ exit 0, zero diagnostics |
| `cargo fmt --all -- --check` | ✅ exit 0 |
| `cargo test --workspace --no-fail-fast` | ⚠️ 115 suites, **721 passed / 1 failed / 1 ignored** |

The single failure is the P2-owned `/dev/urandom` doctor probe — unchanged, unhidden, correctly still
red. Test count went 560 → 721 (+161).

**What was verified by attack, not by reading a report:**

- **SEC-1 holds.** 43 hostile rule names, 16 envelope injections, a cross-scope forgery, and **7
  perfectly-rehashed forged receipts driven through the shipped `ssk.exe`** — every one refused with a
  typed error, exit 21, before any netsh call. The controls that do the work are the rule-name grammar
  and scope re-derivation; the unkeyed digest is *positively asserted* to pass forgeries by a test, so
  it can never again be mistaken for the control.
- **SEC-2 holds.** A writable parent with a protected leaf is caught at every ancestor depth, for all
  five structural rights. Domain Admins and the built-in Administrator account are correctly not
  allowlisted. NULL DACLs, junctions, unknown ACE types and probe failures all refuse (fail-closed).
- **Locale independence is structural.** No branch anywhere reads command output. `classify_show`
  branches solely on the exit code, using the measured asymmetry (§P1 correction above).
- **The 8 broker failures were fixed for the right reason** — the production `icacls` lockdown was
  removed from the *test* path, not from the product. The lockdown itself got strictly tighter (raw
  SID instead of the localized `SYSTEM` name — itself a latent locale bug of exactly the class P1
  exists to kill; `/setowner` before the grant; absolute `icacls` path).
- **The store ACL now executes on the product path.** It initially did not: the lockdown was correct
  but had zero production callers, and `ssk-cli` created the directory with a bare `create_dir_all`
  under a `C:\ProgramData` that grants `BUILTIN\Users:(CI)(WD,AD,WEA,WA)`. A follow-up pass moved
  provisioning into `ssk-winhost::state_dir` (create-or-verify, never create-and-trust) and gated
  every receipt read on it. A squatted directory is **refused, never repaired** — re-ACLing does not
  revoke a handle an attacker already holds.
- **Mutation-tested.** Three guards were verified by deliberately breaking them and confirming a test
  goes red: the race-provenance guard, and the store gate. A fourth mutation revealed that deleting
  the gate *call site* was invisible to the whole suite, so the gate was restructured into a single
  choke point (`winhost_read_receipt_bytes`) that returns receipt bytes only on its far side — a
  caller cannot forget a gate it never invokes — and pinned by an injected-gate test that fails under
  mutation.

**What is NOT verified, and must not be described as such:** no firewall rule has ever been created or
deleted by this software, no service has ever been installed, and `icacls` has never actually locked
down a directory. Those paths cross the UAC boundary and were deliberately not exercised on the
developer's primary machine. See **[`docs/OPERATOR_VM_VALIDATION.md`](OPERATOR_VM_VALIDATION.md)** —
7 legs, en-US and de-DE, with expected before/after `netsh` diffs and what each failure looks like.

**Residual risk after P1** (bounded, disclosed in-code, not eliminated):
- The receipt digest is unkeyed, so anyone who obtains store write access can author a self-consistent
  receipt. The bound is the rule-name grammar plus scope re-derivation — an attacker reaches
  denial-of-rollback, never arbitrary rule deletion.
- A race into the store **leaf's contents** (one level below the provenance guard) remains open during
  the icacls window. Same denial-of-rollback bound.
- Pre-creating the directory is still a denial of service by design: it is now refused rather than
  trusted, which converts "plant a receipt" into "block engage until an administrator clears it".

### P2 — Make the product reachable on Windows  ·  effort M

*Goal: the smallest change that turns "compiles on Windows" into "runnable on Windows".*

- **implement the Windows named-pipe client** in `ssk-ipc/src/client.rs` (tokio `ClientOptions`,
  same CBOR framing); wire `ssk-cli/src/main.rs:401-411` to it and delete the `DAEMON_UNIX_ONLY` stub
- give the pipe explicit `SECURITY_ATTRIBUTES`/DACL and implement the client-SID check that
  `auth.rs:56-60` declares unimplemented; call it from `server.rs:160`
- scope the pipe name per state-dir/user

  > **Corrected 2026-08-02.** This item also said "stop passing `first_pipe_instance` unconditionally".
  > That was a **misreading of the code** — `server.rs` already did `let mut first = true; loop { …
  > .first_pipe_instance(first) … first = false; }`, i.e. it was never unconditional. Worse, removing
  > it would have been a security regression: `FILE_FLAG_FIRST_PIPE_INSTANCE` is the **anti-squat
  > guard**, and dropping it would let a squatter's pipe coexist with ours. The multi-instance defect
  > was entirely the fixed global *name*. The implementation correctly disobeyed this item.
  >
  > Measured while fixing it: a pipe created with NULL `SECURITY_ATTRIBUTES` gets
  > `D:(A;;FR;;;WD)(A;;FR;;;AN)(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;<user>)` — so **Everyone** and
  > **ANONYMOUS LOGON** held `FILE_GENERIC_READ` (instance-exhaustion DoS + response disclosure), and
  > the same user held `FILE_ALL_ACCESS` including `FILE_CREATE_PIPE_INSTANCE` (pipe squatting). That
  > is more precise, and worse, than §2's original "only the default DACL applies".
- bound the pre-auth allocation at `framing.rs:60`; add a connection cap and a read timeout
- replace the `/dev/urandom` probes with `getrandom`/`BCryptGenRandom`; make `winhost doctor` probe
  real elevation and netsh reachability instead of a compile-time cfg
- stop logging a socket path Windows never binds; fix the three integration tests to poll the right
  endpoint; add stale-lock/PID-liveness detection and a Windows shutdown path so a force-kill does
  not brick restart with `os error 80`
- add `version` to the clap derive (git SHA + build date); move the default state dir off the CWD
- validate `profile_id` against the known set and fail closed on unknown ids
- install a tracing subscriber in **every** binary with a JSON layer and rolling file sink; add
  `panic::set_hook` writing a structured crash record; Event Log output for `ssk-svc`

**Exit:** `ssk --version` prints a build identity; `ssk doctor` exits 0; `status`/`list-profiles`/
`activate`/`deactivate` round-trip over the named pipe; an unauthorized process is rejected by the
SID check; two daemons with different state dirs coexist; a Task Manager kill is followed by a clean
restart; every binary writes to a durable rotated log.

**Status: DONE (2026-08-02). The product is reachable on Windows.**

| Gate | Result |
|---|---|
| `cargo build --workspace --all-targets` | ✅ exit 0 |
| `cargo clippy --workspace --all-targets -- -D warnings` | ✅ exit 0 (cache defeated by touching the changed files first) |
| `cargo fmt --all -- --check` | ✅ exit 0 |
| `cargo test --workspace --no-fail-fast` | ✅ **889 passed / 0 failed / 1 ignored**, 120 suites |

**This is the first fully-green workspace test run on Windows.** 721 → 893 mid-phase, then → **889 in
120 suites** after the close-out below merged duplicated tests. The 1 ignored is the same pre-existing
`write_goldens` harness, not a swap. The `/dev/urandom` failure P2 inherited is fixed.

**Close-out: `ssk-diag` extracted (45th crate).** The last unmet exit criterion was "every binary
writes to a durable rotated log" — `ssk-svc.exe` still used `eprintln!` into session 0, where there is
no console to receive it. It could not simply call the existing code: the implementation lived in
`ssk-daemon`, and P2 had added `ssk-daemon → ssk-winhost` for the authenticator, so the reverse edge
would have closed a cycle.

`ssk-diag` is a **leaf crate** (no workspace dependencies at all, verified by `cargo tree`), holding
one copy of the subscriber, rolling sink, panic hook, crash record and OS-CSPRNG probe. This also
retires a named residual: that logic was duplicated between `ssk-daemon` and `ssk-cli`, **and that
exact duplication is what produced the `/dev/urandom` bug in two places** — `ssk-svc` would have been
the third. The two copies differed on only two axes (unconditional vs. `SSK_LOG`-gated stderr;
mandatory vs. optional crash dir), now explicit parameters rather than two bodies of code.

The classic `let _ = init(...)` bug — which drops the `WorkerGuard` immediately and silently discards
every log line — was checked for explicitly on all three binaries and is absent; `ssk-svc`'s guard
spans the whole service lifetime. `ssk-svc` uses `StderrPolicy::Never` because session 0 has no
console, and installs diagnostics at the top of `service_main` rather than in `run()`, so a
hand-launched exe never provisions `%ProgramData%`.

*Honest limit on the accounting:* the net −4 tests cannot be independently reconciled, because the
deleted duplicate modules were never committed — they were untracked working files from P2. The
verifier confirmed the +33 new tests (29 `ssk-diag`, 4 `ssk-svc`) and the +2 suites exactly, but the
claimed 38 deleted duplicates rests on the implementer's report alone. **This is an argument for
committing each phase** rather than carrying P0–P2 as one uncommitted change set.

**Verified live with the real binaries, unelevated** (verbatim verifier output):

```
ssk status         → state=Inactive                          exit=0
ssk list-profiles  → default (Default)                       exit=0
ssk activate --profile default --dest 127.0.0.1:53039
                   → state=Protected active_profile=default   exit=0
ssk deactivate     → state=Inactive                          exit=0
ssk --version      → ssk 0.1.0 / git-sha: unknown / provenance: unknown (declared, not derived)
ssk doctor         → exit=0, all five checks [ok]
```

- **SEC-3 is closed, proven by mutation.** Injecting a permissive `PeerAuthenticator` at the
  composition root made `an_anonymous_impersonation_peer_is_refused_by_the_live_daemon` fail with
  *"the peer check is not on the served path"*. Critically the **positive** test stayed green under
  that mutation — which is exactly why a positive-only test would have been evidence of nothing.
- **The ledger defect is fixed.** `ssk activate --profile totally-made-up-profile` — the literal string
  from §2 — is now refused (exit 2, "known profiles: default") **and appends nothing**: `audit.json`
  holds exactly one entry. Pinned by 4 tests that all go red when the check is neutered.
- **The `os error 80` brick is gone.** A `Stop-Process -Force` leaves the lock file behind and the
  restart still succeeds, because the lock is now a kernel-arbitrated share-mode handle
  (`FILE_SHARE_DELETE` + `FILE_FLAG_DELETE_ON_CLOSE`) rather than file existence. Two daemons with
  different state dirs coexist on distinct, digest-scoped pipe names.
- **The entropy check is real, not trivially ok.** Two draws from the OS CSPRNG (`ProcessPrng`),
  asserting the draws differ, that neither is a constant byte, and a latency budget — a mutation
  neutering the independence and latency assertions turns two tests red.

**Three of this phase's own roadmap premises were falsified by measurement** (`first_pipe_instance`,
the P0 test-debt item, and the assumption that the lifecycle work needed FFI). Each is annotated in
place above rather than quietly rewritten.

**Residual, disclosed:**
- **Rejection of a genuinely different OS user is untested and untestable here** — one interactive
  account, no elevation. Every negative demonstrated is same-user-with-hostile-SQOS. This is the
  headline security property and it rests on an operator script until the VM run.
- **Same-user acceptance is by design.** An unrelated, unelevated PowerShell process with zero
  credentials still receives a full Status DTO. That is correct behaviour — and it means any same-user
  process retains full control-plane access.
- **Same-user pipe squatting is open.** The owner necessarily holds `FILE_CREATE_PIPE_INSTANCE` (the
  accept loop needs it for instances 2..N), and daemon and client share a SID in P2.
  `first_pipe_instance(true)` makes *our* bind fail closed, but a client cannot distinguish the real
  daemon from a squatter. P3's SYSTEM/user split closes it.
- **Build identity is declared, not derived** — no `build.rs`, so `--version` honestly prints
  `git-sha: unknown`.
- **The Unix path was compiled nowhere in this phase**, and the risk has inverted: un-gating the three
  test files means their Unix behaviour is governed by new `endpoint_for`/readiness code that has never
  been built on Linux. P0's CI matrix is what will catch this.

### P3 — Host the privileged broker for real  ·  effort L

*Goal: give the P0/P2 security core a process to live in. Depends on P1 (safe before elevated) and
P2 (authenticated before it fronts SYSTEM).*

- make `ssk-svc.exe` actually host `ssk_netd_helper::Broker`, serve the privileged pipe, apply the
  ProgramData DACL, and run `Broker::recover()` at startup — replacing the deliberate no-op
- add a `CommandEnvelope` transport (framing + client) and a versioned handshake
- implement `EgressObserver` in `ssk-winhost` so `os_rule_present` and the `Recovery::Inconsistent`
  alarm read from the real firewall
- **route `ssk winhost killswitch` through the broker** instead of constructing
  `WindowsFirewallEnforcer` directly, so auth, nonce rejection, op-lock, version gate and the
  hash-chained audit are on the path users actually take
- replace the daemon's hardcoded `kill_switch: false` with authoritative broker status
- add cross-session refcounting for the firewall rule; move toward WFP dynamic session filters so a
  broker crash cannot strand a severed machine
- add native Windows integration tests exercising the FFI (admin-gated engage/release with rule
  diffs, SCM lifecycle, pipe round-trip)

**Exit:** an elevated service owns the kill-switch; the CLI performs no privileged action itself;
killing and restarting the service recovers correct state and raises `Inconsistent` when the OS rule
was removed underneath it.

### P4 — Build the actual product promise: ingress and dispatch  ·  effort XL

*Goal: make traffic protection exist. The largest phase; the product's identity depends on it.*

> **Architecture decided (2026-08-03), design-spiked with real evidence on this machine.**
> Superseding everything below the line: **WFP/WinDivert is no longer the ingress mechanism.**
> The user chose a TUN-based approach (Wintun) over a raw WFP callout driver specifically to avoid
> building/signing a custom kernel driver, and chose to keep the dispatch model as a **per-flow smart
> router** (not a classic single-tunnel VPN client) with **OpenVPN as one additional selectable
> adapter**, subprocess-orchestrated rather than natively reimplemented. See
> `docs/P4_INGRESS_DESIGN.md` for the full design-spike findings, evidence, and the corrected
> licensing/signing facts (the premise "Wintun is MIT-licensed" was itself imprecise — see below).

**Corrected facts from the spike, replacing assumptions:**
- Only the `wintun`/`wintun-bindings` **Rust wrapper crates** are MIT (verified: extracted and read
  `LICENSE` from both). The vendored `wintun.dll` itself is under a separate **WireGuard LLC
  proprietary "Prebuilt Binaries License"** — permissive enough for this project's subprocess/
  Permitted-API use (§3d of that license) but **not MIT**, and must get its own `NOTICE`/
  third-party-license entry in P6, not be folded into a Cargo `deny.toml`-style MIT claim.
- The outer `wintun.dll` carries a valid but **expired (2021) WireGuard LLC / DigiCert EV Authenticode
  signature** (validated only via an RFC3161 timestamp) — **not** a Microsoft WHQL/attestation
  signature on the DLL itself. The embedded kernel `.sys` resource inside the DLL (the thing actually
  subject to Windows driver-signing enforcement) was **not independently verified** — this remains a
  real open item for the operator VM, not a closed question.
- **`WintunCreateAdapter` requires Administrator** (vendor-documented; matches this project's existing
  P3 pattern) — so adapter creation, DNS-server takeover, and `openvpn.exe` spawning (OpenVPN's own
  client also creates a privileged TUN/TAP-class adapter) all sit on the **privileged-broker side**
  (`ssk-svc`/`ssk-winhost`), never in `ssk-daemon`, using the identical engage/release request pattern
  P2/P3 already built and validated over `ssk-ipc`.

**The routing-loop problem (the hardest open question since P0) is resolved as a hybrid, not a single
mechanism:**
1. **Lane 1 — system-proxy listener** (SOCKS5/HTTP-CONNECT `TcpListener`, unchanged from the original
   plan): covers proxy-aware applications with zero new stack risk.
2. **Lane 2 — fake-IP + narrow-range Wintun**: a DNS resolver-server (reusing `ssk-netcore::dns.rs`'s
   existing RFC 1035 encode/decode helpers) hands out synthetic addresses from a non-routable
   `198.18.0.0/15`-class range; **only that narrow range** is routed through the TUN adapter — verified
   safe on this machine's real routing table (Windows routing is longest-prefix-match, confirmed via
   `route print`, so a `/15` TUN route coexists with the real default route with zero interference).
   Failure mode is safe-by-construction: an unhandled fake IP just times out, nothing on the real
   internet answers there. A minimal embedded TCP terminator (new crate `ssk-tunstack`, wrapping
   `smoltcp`, `forbid(unsafe_code)`, injected frame-source/sink seam mirroring
   `ssk-netd-helper::FrameTransport`) terminates handshakes for that narrow range only — **not** a
   general-purpose internet-facing TCP/IP stack.
3. **Lane 3 — OpenVPN**, as originally scoped: a 6th selectable adapter, subprocess-orchestrated,
   broker-hosted, using `route-nopull` + explicit routes for split-tunnel behavior.
4. A new, small, unprivileged prerequisite: **`IP_UNICAST_IF`** (a per-socket Win32 option, not
   privilege-gated) lets the daemon's own re-dispatch/DNS-resolver sockets bypass the TUN-ward route
   entirely — this is what makes "TUN captures a narrow range" safe without destination-based
   exclusions.

**Explicitly deferred out of P4, as a genuine, separately-sized future phase — this is the single most
consequential open scoping decision, and it is the user's to make, not something resolved here:**
full `0.0.0.0/0` TUN capture with a general-purpose userspace TCP/IP stack (arbitrary internet TCP
correctness: window scaling, SACK, PMTU, full IPv6, general UDP NAT) would cover non-DNS-visible
traffic (hardcoded destination IPs, DoH/DoT to a hardcoded resolver, QUIC connection-ID reuse) that
Lanes 1–3 cannot. Costed at XL **on its own**, separate from this phase's XL. If "the full product
promise" in §6 is meant literally (zero unprotected gaps), P4 as scoped here undersells the true v1.0
cost significantly. If Lanes 1–3 (the dominant real-world case: proxy-aware apps + anything using
normal system DNS + an explicit VPN adapter) are the accepted v1.0 scope, XL is a reasonable, arguably
conservative estimate for this narrower target — with the gap surfaced honestly via a `dns_unprotected`
state (already named in `docs/DESKTOP_CLIENT_ARCHITECTURE.md`), never silently absent.

**Sub-phases** (see `docs/P4_INGRESS_DESIGN.md` for full work-item detail and dependency graph):

| Sub-phase | Goal | Effort | Depends on |
|---|---|---|---|
| P4a | Real config schema (adapters incl. OpenVPN, per-app rules); `LoadedConfig` actually consumed | M | — |
| P4b | Lane 1: system-proxy ingress, real `EgressSession` byte-pumping, real `FlowDescriptor` | L | P4a (loose) |
| P4c | `IP_UNICAST_IF` prerequisite | S | — |
| P4d | Wintun integration spike (pick crate, confirm unelevated failure mode, `.sys` signature) | S | — (blocks P4e) |
| P4e | TUN adapter lifecycle in the privileged broker | L | P4d |
| P4f | Fake-IP DNS server + narrow-range routing | M | P4c, P4e |
| P4g | Minimal `smoltcp`-based TCP terminator for the fake-IP range | L | P4e, P4f |
| P4h | Packet-to-flow classification bridge (unifies Lane 1 + Lane 2 on one dispatch spine) | M | P4b, P4g |
| P4i | Lane 3: OpenVPN adapter (`ssk-vpnctl`, subprocess + management-interface client) | L | P4a; parallel to P4d–h |
| P4j | Integration tier: full path proven end-to-end, Windows **and** Linux | M | P4h, P4i |

**Exit:** a real application's traffic enters SSK via Lane 1 or Lane 2, is classified by a
config-declared rule, dispatched through a config-declared adapter (including OpenVPN), and arrives —
proven by an automated Windows E2E test. Non-DNS-visible traffic is explicitly out of scope for this
exit criterion (see the deferred-scope note above) unless the user decides otherwise.

### P5 — Make the analysis honest and connected  ·  effort L

*Goal: convert the ~21.7k LOC theory mass from a demo over a fixture into something true about the
user's machine. First work item is shared with P4 and should be scheduled jointly.*

- **enrich the capture model first**: carry owning PID + process image path through
  `FlowRow → TrafficWindow` (`connections.rs:151-166` parses the PID and discards it); keep the local
  endpoint for TCP (today ~14 of ~49 listening sockets collapse to `tcp://0.0.0.0:0`); add AF_INET6
  (33 IPv6 sockets were invisible on the test host); stop overloading `status` with both HTTP codes
  and TCP MIB states
- only then wire `WindowsConnectionSource` into `SystemPipeline` and add `ssk system run --live`
- replace the self-referential `TargetProfile` with a persisted per-host baseline and pass a real
  `ChameleonPolicy` decision
- compute `parallax_consistent`/`replay_equal` from real evidence, or pass `false`
- **replace `ssk-stitch`'s four hardcoded `true` flags with real predicates**, restoring
  BoundaryGate, ReplayGate, FocusGate, two PCH projectors, three Gabriel cells and BCIK closure to
  being able to fail
- add property coverage for the spectral axis; calibrate the hardcoded QLOGIC thresholds against a
  golden corpus
- **split the workspace**: move the 8 binary-unreachable crates and the GUI-only subtrees (~12.8k
  LOC) into a separate theory workspace; fold the four placeholder crates into `ssk-runtime`

**Exit:** `ssk system run --live` produces a verdict derived from real PID-attributed dual-stack
flows against a persisted baseline; no gate in the vector is unconditionally satisfied; the product
workspace contains only crates reachable from a shipped binary.

### P6 — Distribution and operability  ·  effort L

*Goal: something a Windows user can obtain, install, trust, and update.*

- rewrite `release.yml` as a matrix build (windows/linux/macos, x86_64 + aarch64) uploading the
  actual binaries with SHA-256 checksums and an SBOM
- add `LICENSE` (full Apache-2.0 text) + `NOTICE` in every artifact; add `CHANGELOG.md` and a
  documented tag → build → sign → notes process
- app identity: `.ico` set, tray icon, exe version resource
- **Windows installer** (WiX/MSI or Inno Setup): per-machine install to Program Files, state under
  `%ProgramData%`, SCM registration of the elevated helper, and an uninstaller that removes the
  service **and releases any engaged kill-switch** — an uninstall that leaves egress severed bricks
  the machine
- **Authenticode signing** (EV cert or Azure Trusted Signing) for all binaries and the installer
- elevation design: unprivileged app + one install-time elevated service registration, never
  per-operation `runas`; define the path when the user declines UAC
- signed-manifest updater with signature verification, staged download, service-aware sequencing
  (stop → replace → restart → re-verify) and rollback
- opt-in crash reporting with explicit consent, a stated no-telemetry-by-default position, privacy
  policy, EULA
- user-facing docs — all 35 existing `.md` files are internal spec/audit prose
- repo hygiene: remove the 814 KB of committed PDFs and the zip, consolidate the 15 overlapping root
  specs, set `deny.toml` `multiple-versions` to deny, collapse the `getrandom` 0.2/0.3/0.4 and `rand`
  0.8/0.9 splits, close the 8 stale dependabot branches

**Exit:** a signed MSI on a clean Windows 11 VM installs, registers the service, passes SmartScreen,
runs `ssk doctor` green, performs an engage/release cycle, updates to a newer signed build, and
uninstalls cleanly leaving no service and no firewall rule.

### P7 — Desktop GUI  ·  effort XL

*Goal: the thing a user double-clicks. Last on purpose.*

The existing `ssk-tauri-bridge` is a leaf crate with **zero consumers in either direction** and no
dependency on `ssk-ipc`. Its 271-LOC frontend binds to `PanelSnapshotDto` — a type that exists in
**no Rust file**. `connections_view(tcp: &[u8], …)` takes raw IP Helper bytes that no reachable
`ssk-winhost` API produces (`mod sys` is crate-private), so the tested view and the tested capture
**cannot currently be connected**. The UI has zero buttons and zero inputs, and never refreshes.

- define `PanelSnapshotDto` with `deny_unknown_fields` and a golden per state
- fix the P3 seam: expose a public raw-table accessor, or change `connections_view` to take
  `&[FlowRow]`
- fix `classify()` (`state.rs:71-80`), which never reads `os_rule_present`, so an engaged switch with
  an absent OS rule is classified `Engaged` — contradicting that variant's own doc
- construct and test `BridgeError` (never constructed by any function today); add the missing
  `SystemVerdictViewDto` golden and a drift guard for the 7 unread fixtures
- reconcile the three coexisting state models (7 `PanelState`, 8 `DaemonState`, 18 product states in
  `DESKTOP_CLIENT_ARCHITECTURE.md`); adopt the `ssk-ipc` `Event` enum that was built for this and
  ignored
- add the Tauri v2 scaffold (`tauri.conf.json`, `build.rs`, read+write commands, `[[bin]]`)
- **add write affordances** — the entire P2 control layer currently has no user-reachable surface —
  and replace the one-shot `DOMContentLoaded` invoke with an event/push channel
- add a frontend build + DOM test runner rendering every fixture, and ts-rs/schemars TS generation
  with a `git diff --exit-code` drift guard — the rule "green binds only to `protection_confirmed`"
  is today enforced by a code comment and nothing else

**Exit:** a signed, installed app shows live PID-attributed connection state and real kill-switch
status, can engage/release through the elevated broker, updates without polling, renders every
fail-closed state under an automated DOM test, and **never displays green that is not backed by a
confirmed OS rule**.

---

## 5. Open questions that need a decision or a VM

These are genuinely unresolved. Several change what the plan should be.

1. **Nobody has ever observed a successful kill-switch engage → release cycle**, on any machine, in
   any locale. The English happy path is inferred from unit tests over hand-written fixtures, not
   from a rule appearing in Windows Firewall. Needs an elevated en-US VM with a before/after
   `netsh advfirewall firewall show rule` diff, then the same on de-DE.
2. ~~**The 8 `ssk-netd-helper` failures may be an unelevated-caller artifact.**~~
   **RESOLVED 2026-08-02 — hypothesis (a): it works when elevated, and that is itself the bug.**
   Established by controlled experiment, not inference:
   - Running `store.rs:174`'s exact icacls command on a scratch directory reproduced the lockout
     end-to-end: icacls exits 0, the resulting DACL is exactly `BUILTIN\Administrators:(OI)(CI)(F)`
     + `NT AUTHORITY\SYSTEM:(OI)(CI)(F)`, and a write that had succeeded on that same directory
     seconds earlier then failed with access denied — as did even `Get-ChildItem`.
   - **Control:** the identical command granting the *running user's own SID* instead of
     `*S-1-5-32-544` → write succeeds. This isolates the cause to *which principal is granted* and
     rules out `/inheritance:r` itself, an icacls failure, or a tempdir artifact.
   - **Mechanism:** `whoami /groups` shows `S-1-5-32-544` present but flagged
     `SE_GROUP_USE_FOR_DENY_ONLY`, at Medium integrity — a UAC-filtered admin token. The
     Administrators ACE grants such a process *nothing*.

   **Consequence for the P1 fix:** an elevated CI runner will make these 8 tests pass, which would
   be a **false green** — it would certify a store that any unelevated caller cannot use. The fix is
   therefore *not* "run the tests elevated". It is: grant the running principal in addition to
   SYSTEM + Administrators, or apply the restrictive DACL only when actually elevated, plus make the
   store test-injectable so the DACL path is exercised deliberately rather than incidentally, plus a
   typed `NOT_ELEVATED` preflight error. All four are already listed in P1.
3. **SEC-1 was demonstrated only up to the elevation boundary.** That a forged receipt would
   actually delete an arbitrary firewall rule under elevation is a strong inference from the code
   path, not an observed outcome. Confirm in a disposable VM.
4. ~~**WFP/WinDivert ingress (P4) is estimated, not scoped.**~~ **PARTLY RESOLVED (2026-08-03) by a
   design spike — but not a clean win, and the mechanism changed.** WFP is no longer in play; P4 uses
   Wintun + fake-IP DNS + OpenVPN-as-adapter instead (see P4's own section above and
   `docs/P4_INGRESS_DESIGN.md`). Driver-signing risk is genuinely lower than a from-scratch WFP
   callout would have been — Wintun's `.dll`/driver is pre-signed by WireGuard LLC, not something
   this project would sign itself — but the embedded kernel `.sys`'s actual signature chain was **not
   independently verified**, only inferred from vendor documentation. And the spike surfaced a **new
   risk of comparable weight the original question didn't anticipate**: a DNS-server-takeover
   subsystem and an `openvpn.exe` subprocess-spawn heuristic, neither of which exists under a
   WFP-only framing. Net effect on total unknown-unknowns: roughly a wash, not a reduction. Still
   needs an elevated VM to confirm the unelevated failure mode's exact error code and the embedded
   `.sys` signature (see `docs/P4_INGRESS_DESIGN.md`'s unverified list).
5. **Nothing has been measured under load.** No throughput, latency-vs-direct, memory, or leak
   testing. For software that sits in the path of all traffic this is a material unknown.
6. **Whether the spectral metric has discriminative power is currently unknowable** — because
   `TargetProfile` is built inside `evaluate()`, the distance path has never been exercised with two
   different inputs, in production or in tests. The theory could be excellent or it could be
   numerology; the wiring makes the question untestable, which is itself the finding.
7. **AV/EDR and SmartScreen interaction is untested.** An unsigned binary that installs a SYSTEM
   service, writes firewall rules, and enumerates every process's connections is exactly the
   behavioral profile heuristics flag. Signing is necessary but very likely not sufficient.
8. **Is the Linux CI actually green?** The `clippy` failure is in a non-cfg-gated lib function and
   should fire on Linux too. Either the badge is stale relative to rustc 1.95, or the invocation
   differs. Check the actual latest Actions run rather than trusting the badge.

---

## 6. Scope decision — DECIDED 2026-08-02

Two paths were on the table:

1. **Re-scope to what is nearly real** — a deterministic, replay-verifiable security-analysis and
   audit tool with a real kill-switch and live connection visibility, dropping transparent
   interception. Reaches a shippable, honest v1.0 after P0–P3 + P6, skipping the XL phase.
2. **The full product promise** — policy-driven traffic protection, with transparent ingress.

**Decision: path 2.** v1.0 is the full product. P4 (ingress) stays in the critical path and is not
deferred to v2.0.

**Consequences that bind the earlier phases:**

- The kill-switch must be designed toward **WFP dynamic session filters**, not settled permanently
  on netsh/COM. P1 still delocalizes and hardens the netsh path — that work is needed now and is
  not wasted — but P1 and P3 should treat netsh as the interim mechanism behind a stable interface,
  not as the destination. The WFP filter is what makes a broker crash unable to strand a severed
  machine (P3).

  > **Corrected 2026-08-03.** The line above originally justified this as sharing infrastructure
  > with P4 ("the same subsystem P4 needs for redirection") — that linkage is now **wrong**. The
  > P4 design spike resolved ingress as Wintun + fake-IP DNS + `IP_UNICAST_IF`, not WFP (see P4's
  > section above). If the kill-switch still wants WFP dynamic filters, it must be justified on its
  > **own** merits alone — crash-survival semantics, not shared plumbing with ingress.

- ~~The P4 design spike ... should be scheduled early and in parallel with P1/P2~~ **DONE
  (2026-08-03).** The spike ran after P0–P3 rather than in parallel with them, and its content
  turned out to be Wintun-specific (licensing, embedded-driver signature, unelevated failure mode),
  not WFP-sublayer-arbitration — much lighter than originally feared, and it did not end up
  changing the P3 kill-switch design at all, since the two are now architecturally independent. The
  "schedule early because it changes P3" reasoning did not hold; noted for calibration on future
  "spike early" recommendations in this document.
- P6's signing and installer work is still load-bearing, not optional: an unsigned binary that
  creates a network adapter, takes over DNS settings, and spawns an external `openvpn.exe` process
  is at least as strong an AV/EDR/SmartScreen heuristic signal as a WFP component would have been
  — the spike found a *different* set of flags, not fewer of them (§5.7, §5.9).
