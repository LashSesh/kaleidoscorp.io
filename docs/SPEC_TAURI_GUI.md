# Specification — SSK Desktop GUI (Tauri) + Privileged Broker

**Status:** Draft for review, revision 2. Specification only — P0 (§12) is the only slice cleared
for implementation.
**Stack decision:** Tauri v2 (Rust backend links the SSK crates; framework-free HTML/CSS/JS frontend
in WebView2). Chosen over WinUI 3 / Avalonia / egui / Slint on one decisive axis: the backend *is*
Rust, so it reuses the pure `ssk-*` controllers in-process with **zero FFI** and no re-declared
types. Aligns with the direction the repo already carries (`docs/DESKTOP_CLIENT_ARCHITECTURE.md`
names `ssk-tauri-bridge`; `crates/ssk-ipc/src/lib.rs` anticipates "a Tauri GUI bridge").

> Honesty rule: **[EXISTS]** = present in the tree today (verified in §0); **[NEW]** = to be built;
> **[MODIFY]** = additive change to an existing crate. A mis-read control state on a security panel
> is a *safety* defect, so §7 fail-closed rules and §5 protocol rules are normative, not stylistic.

---

## 0. Evidence preflight (verified before this spec leaned on any symbol)

Requirement: no `[EXISTS]` claim without a matching symbol in the tree. Verified with `rg`/`sed`
against `crates/` on this revision:

| Claim | Symbol / fact | Location | Status |
|---|---|---|---|
| Kill-switch state machine | `KillSwitch::{arm, state, engage, release, override_engage, audit_entries, verify_audit}` | `ssk-boundary/src/lib.rs:194+` | ✅ |
| Enforcement seam (rollback receipt) | `trait BoundaryEnforcer{engage,release}`, `struct EnforcementReceipt{receipt_id,scope_label,prior_state}` | `ssk-boundary/src/lib.rs:91,125` | ✅ |
| **Release is broker/switch-managed** | `KillSwitch::release(auth, enforcer)` takes the **internally held** receipt (`self.receipt.take()`), not a client-supplied one | `ssk-boundary/src/lib.rs:305,316` | ✅ |
| Kill-switch audit is hash-chained | `BoundaryAuditEntry{seq,prev_hash,entry_hash}`, `verify_audit()` recomputes+links | `ssk-boundary/src/lib.rs:376` | ✅ |
| Kill-switch is auth-gated | `engage`/`release` require `AuthorizationManifest::is_valid_for(control_use)` | `ssk-boundary/src/lib.rs:283,309` | ✅ |
| Service lifecycle gate | `ServiceHost::{stage,state,handshake_complete,health,audit_entries}` | `ssk-service-host/src/lib.rs:284+` | ✅ |
| Session capability token | `struct SessionToken([u8;16])`, `generate()`, minted per named-pipe connection | `ssk-ipc/src/auth.rs:8`, `server.rs:160` | ✅ |
| Named-pipe transport | `serve_named_pipe(pipe_name, handler)` | `ssk-ipc/src/server.rs:136` | ✅ |
| **Client-SID check is a gap** | `auth::windows::CLIENT_SID_CHECK_IMPLEMENTED = false` | `ssk-ipc/src/auth.rs:59` | ⚠️ gap |
| CBOR framing + frame cap | `[u32 len][ciborium body]`, `MAX_FRAME_LEN = 16 MiB` enforced on read | `ssk-ipc/src/framing.rs:15,51` | ✅ (generic) |
| Firewall enforcer (real) | `WindowsFirewallEnforcer` impl `BoundaryEnforcer` | `ssk-winhost/src/firewall.rs:486` | ✅ (Windows) |
| System verdict surface | `SystemPipeline::{evaluate,verify_ledger}`, `SystemVerdict` | `ssk-system/src/lib.rs:81,120,265` | ✅ |
| Forensic ledger verify | `AuditLedger::verify_against_head` | `ssk-netadmin/src/audit.rs:203` | ✅ |
| Durable audit sink | `FileAuditStore::load -> LoadReport` | `ssk-audit-store/src/lib.rs:84` | ✅ |

**Not present today (all [NEW]):** nonce / anti-replay, per-command command-auth (token is minted
but not required per request), `deny_unknown_fields` strict decode, tighter privileged-frame cap,
operation lock, idempotency keys, `expected_state_version`, a ProgramData ACL'd store, the
authoritative `KillSwitchStatus`, and a `KillSwitch` rehydration constructor for crash recovery.

**P0 preflight gate (requirement 11):** the P0 implementation MUST begin by re-running this symbol
check (`rg` for each symbol above) and abort if any `[EXISTS]` row no longer resolves, before a
single line calls into those crates.

---

## 1. Purpose & non-goals

**Purpose.** A local control panel for the SSK system on Windows 11: view system state and gate
verdicts, read and verify the audit ledger, inspect connections/routes, and drive the two
privileged operations that matter — the **kill-switch** (sever/restore all outbound egress) and the
**Windows service lifecycle**.

**Non-goals (this spec).** The GUI holds **no privileged and no business logic** — it is a view +
driver. No auto-update in v1. No MSIX in v1 (native Tauri MSI/NSIS). The older
`docs/ROADMAP_DESKTOP_GUI.md` HTTP sketch (`POST /run`) is **superseded** by the real `ssk-ipc`
contract + the broker protocol here.

---

## 2. Authoritative topology (single writer — no split-brain)

**Decision: `GUI → helper-as-runtime`.** The elevated broker `ssk-netd-helper` is the **single
authoritative owner of the security domain** (kill-switch + service lifecycle). It is the only
writer of kill-switch state and the only holder of the durable receipt/audit store.

```
┌──────────────────────────────────────────────────────────────┐
│  WebView2 frontend  (framework-free HTML/CSS/JS)  unprivileged │
└───────────────▲──────────────────────────────────────────────┘
                │ Tauri IPC — JSON (serde_json), NOT CBOR (§10)
┌───────────────┴──────────────────────────────────────────────┐
│  ssk-tauri-bridge  [NEW]  GUI backend (safe Rust) unprivileged │
│   • in-process reuse (no pipe): SystemPipeline, audit verify,   │
│     KillSwitch/ServiceHost READ, winhost pure parsers          │
│   • privileged verbs → forwarded to the broker over the pipe   │
└───────────────▲──────────────────────────────────────────────┘
                │ ssk-ipc named pipe, length-prefixed CBOR,
                │ client-SID authenticated + command-authed (§5)
┌───────────────┴──────────────────────────────────────────────┐
│  ssk-netd-helper  [NEW]   elevated broker  (SYSTEM)            │
│   • THE authoritative owner of kill-switch + service state     │
│   • durable ACL'd store in ProgramData (§3)                    │
│   • routes each verb: cmd-auth → op-lock → idempotency →        │
│     state-version → KillSwitch/ServiceHost gate → enforcer →    │
│     persist → audit-append → authoritative status              │
│   • drives ssk-winhost (WindowsFirewallEnforcer, …)           │
└──────────────────────────────────────────────────────────────┘

  sskd (existing daemon)  — SEPARATE, unprivileged, egress-only.
  It NEVER writes kill-switch/service state. If it needs security
  state it READS the broker's authoritative status. Single writer
  = the broker. This is the no-split-brain rule.
```

**Why helper-as-runtime, not GUI→sskd→helper:** the kill-switch needs one persistent authoritative
owner with a durable store and crash recovery. Routing through `sskd` would add a second stateful
hop that could disagree with the broker (split-brain) and would couple the security panel's
availability to the egress daemon. The broker owns security; `sskd` owns egress; they do not share
security state.

---

## 3. Durable, ACL-protected state store (replaces `%TEMP%`)

**Decision:** all privileged state — the current `EnforcementReceipt`, the kill-switch audit
journal, and the authoritative status snapshot — lives in a **durable, ACL'd store**, not `%TEMP%`.

- **Path [NEW]:** `%ProgramData%\ScorpioSync\state\` (resolved via the `ProgramData` known folder;
  env `ProgramData` fallback). Tests inject an arbitrary directory.
- **ACL [NEW, Windows]:** the directory DACL grants **only** `SYSTEM` and `BUILTIN\Administrators`
  (full), inherits to children, and removes `Users`. Applied on first create; re-asserted on
  startup. On non-Windows (CI) the ACL step is a documented no-op and the injected dir is used.
- **Write discipline:** every state mutation is an atomic write (temp file in the same dir +
  `fsync` + atomic rename), so a crash mid-write never yields a torn snapshot. The journal is
  append-only and hash-chained (mirrors `ssk-boundary`'s in-memory chain; the on-disk head anchors
  it against truncation, reusing the `ssk-audit-store` discipline).
- **Rationale:** `%TEMP%` is world-writable-ish, user-scoped, and cleared aggressively — unfit to
  hold the single source of truth for whether egress is currently severed.

---

## 4. Authoritative `KillSwitchStatus` [NEW]

The broker's status is the authoritative answer to "is egress severed right now, and can we prove
it?" It is a reconciliation of four inputs, never a single flag:

```
KillSwitchStatus {
    logical_state:   Armed | Engaged | Released,   // from the persisted journal
    receipt:         Option<EnforcementReceipt>,    // the held rollback receipt
    os_rule_present: Option<bool>,   // enforcer-observed actual OS firewall rule (None if unknown)
    audit_head:      Digest,          // hash-chain head of the persisted journal (+ last seq)
    state_version:   u64,             // monotone; bumped on every successful transition (§8)
    recovery:        Consistent | Reconciled | Inconsistent,
}
```

- **`Consistent`** — journal and observed OS rule agree (Engaged ⇒ rule present; Released ⇒ absent).
- **`Reconciled`** — a crash was detected and the journal was replayed to a coherent state.
- **`Inconsistent`** — journal says Engaged but the OS rule is absent (or vice-versa). This is a
  **fail-closed, operator-visible alarm**, never silently smoothed. The GUI must render it red.

`recover()` runs on broker startup: read the journal (verify the chain, honor the on-disk head),
determine `logical_state` + `receipt`, ask the enforcer whether the rule is actually present, and
compute `recovery`. This is what the crash-recovery test (§12) exercises.

---

## 5. Broker command protocol [NEW] (auth, anti-replay, framing, strict decode)

Every privileged request is a `CommandEnvelope`, decoded under **strict CBOR** and authenticated
before any effect:

```
CommandEnvelope {
    session_token:   SessionToken,      // [EXISTS] minted at connect; now REQUIRED per command
    nonce:           [u8; 16],          // anti-replay; unique per command within a session
    idempotency_key: [u8; 16],          // dedup key (§8)
    expected_state_version: u64,        // optimistic concurrency (§8)
    command:         Command,           // GetStatus | EngageKillSwitch | ReleaseKillSwitch | …
}
```

Enforced, in order, before the verb runs:
1. **Command-auth [NEW].** `session_token` must equal the token minted for this connection.
   Mismatch → reject, no effect. (Today the token is minted but not checked per request.)
2. **Anti-replay [NEW].** `nonce` must be unseen in this session (bounded LRU/set); a replayed
   nonce → reject. Combined with the per-connection token this stops replay of a captured frame.
3. **Frame limits [NEW, tighter].** Privileged frames are capped well below the generic 16 MiB
   (e.g. 64 KiB) — a `CommandEnvelope` is tiny; anything larger is hostile → reject pre-decode.
4. **Strict CBOR [NEW].** All broker DTOs derive `#[serde(deny_unknown_fields)]`; decode rejects
   unknown fields and trailing bytes. No lenient/partial decode of a security command.
5. **Client-SID [NEW].** (Transport layer, §11) the connection is rejected unless the peer SID is on
   the allow-list; `CLIENT_SID_CHECK_IMPLEMENTED` becomes a real check.

A response is `BrokerResponse::{Ok(status|payload), Rejected(reason), Failed(error)}` — a rejection
is explicit and typed, never a silent drop.

---

## 6. Per-verb rollback / recovery contract [NEW]

Every privileged verb declares, and the broker enforces, an explicit contract. Persistence happens
**only after** the OS effect succeeds, so a failure never leaves a half-committed journal.

| Verb | Effect | Success commit order | Rollback on failure | Recovery on crash |
|---|---|---|---|---|
| `EngageKillSwitch` | `enforcer.engage(scope)` → receipt | 1) enforcer.engage OK → 2) persist receipt+journal+status (atomic) → 3) bump version | enforcer error → **no** state change, **no** persisted receipt (KillSwitch stays pre-engage); return `Failed` | journal replay: if Engaged+receipt persisted, status Engaged; reconcile with OS rule (§4) |
| `ReleaseKillSwitch` | `enforcer.release(held receipt)` | 1) enforcer.release OK → 2) persist Released+journal+status → 3) bump version | enforcer error → receipt **retained**, state stays Engaged; return `Failed` | if Released persisted, status Released; if a crash happened between OS release and persist, reconcile finds rule absent + journal Engaged → `Inconsistent` alarm |
| `GetStatus` | pure read | none (read-only) | n/a | n/a |

The receipt is **broker-managed** (requirement 7): the client never sends a receipt.
`ReleaseKillSwitch` carries only `idempotency_key` + `expected_state_version`; the broker releases
using the receipt it holds in the durable store (matching `KillSwitch::release`'s internal-receipt
semantics, verified in §0).

---

## 7. Fail-closed & no-overclaim rules (normative)

1. **Never fabricate a green.** Broker unreachable, verdict unknown, or ledger unverified → render
   `Unknown`/`Degraded`/`Unverified` verbatim, never a default "ok".
2. **Kill-switch truth is the broker's authoritative status (§4),** never an optimistic client
   cache. `Inconsistent` renders as a red alarm.
3. **Single source of truth for DTOs.** No hand-mirrored types on any boundary (§10).
4. **Audit is verifiable in-panel** (`verify` / `verify_against_head`); a truncated/tampered chain
   is visible, not smoothed.
5. **Privileged verbs are audited** through the kill-switch/service hash-chained journal; the panel
   can show the resulting entry.

---

## 8. Concurrency & idempotency [NEW]

- **Operation lock.** A single broker-wide async lock serializes privileged verbs; two concurrent
  `EngageKillSwitch` never race the enforcer. Read verbs (`GetStatus`) do not take the write lock.
- **Idempotency keys.** The broker keeps a bounded map `idempotency_key → (state_version, result)`.
  A repeated key returns the cached result **without** re-executing the OS effect (a retried engage
  after a dropped response does not double-apply).
- **`expected_state_version`.** Optimistic concurrency: the client sends the version it believes is
  current; if it differs from the broker's, the verb is `Rejected(StaleVersion)` — the client must
  re-read status first. Every successful transition bumps the version by exactly 1.

---

## 9. Tauri / WebView2 hardening [NEW]

- **CSP:** a strict `Content-Security-Policy` (no remote origins; `default-src 'self'`; no inline
  script except hashed); all assets bundled, none fetched.
- **Tauri allowlist/capabilities:** only the specific `#[tauri::command]`s the UI needs are exposed;
  `shell`, `fs`, `http`, and arbitrary `invoke` are disabled. No `dangerousRemoteDomainIpcAccess`.
- **No Node/remote:** framework-free frontend; no dev server in release; `devtools` disabled in
  release builds.
- **WebView2:** pinned Evergreen runtime; navigation locked to the bundled app origin
  (`tauri://`/`https://tauri.localhost`); external links open in the OS browser, never in-app.
- **IPC surface:** the bridge exposes only typed commands returning typed DTOs; no string-eval, no
  passthrough of arbitrary bytes from JS to the pipe.

---

## 10. DTO schema, fixtures & state model [NEW] (no raw CBOR over JS IPC)

Correction to revision 1: **Tauri JS↔Rust IPC is JSON** (serde_json), not raw CBOR. CBOR is the wire
format of the **helper named pipe only**. The frontend never sees CBOR.

- **Single source of truth:** DTOs are defined once in Rust (`ssk-ipc` + broker types). TypeScript
  types are **generated** from them (e.g. `ts-rs` or a `schemars` JSON Schema emitted at build) —
  never hand-written on the JS side.
- **Fixtures:** a committed fixture set (golden JSON) for every DTO and every fail-closed state
  drives frontend rendering tests without a live backend; the same fixtures are asserted round-trip
  in Rust so schema and fixtures cannot drift silently.
- **State model:** an explicit, documented UI state machine (e.g. `Disconnected → Connecting →
  Ready → {Engaged, Released, Inconsistent, Degraded}`) with the allowed transitions; the panel
  renders strictly from this model, so an unknown/uncovered state is a visible defect, not a blank.
- **Contract test:** a CI check asserts the generated TS types match the Rust DTOs (regenerate →
  diff must be empty), guarding cross-language drift — the guard a C# GUI could not have had.

---

## 11. P0 decisions (moved out of "open questions")

These were open in revision 1; they are **decided** now because P0 depends on them.

- **Broker delivery:** a **dedicated elevated Windows service** (`ssk-netd-helper`) hosting the
  named pipe and owning the durable store — **not** a per-operation `runas` helper. Rationale: the
  kill-switch needs a persistent authoritative owner and crash recovery, which a transient elevated
  process cannot provide.
- **SID allow-list:** an explicit list of principal SIDs permitted to drive privileged verbs,
  persisted in the ACL'd store. Default: the installing administrator account + `LocalSystem`.
  Unknown SID → connection rejected (fail-closed). Configurable only by an already-privileged actor.
- **Daemon vs. helper responsibility:** the **helper owns the security/privileged domain** and is
  authoritative for kill-switch + service state; **`sskd` owns the unprivileged egress domain** and
  never writes security state (§2). This is the single-writer resolution of the split-brain risk.

---

## 12. P0 — the vertical slice (the ONLY slice cleared to implement now)

Goal: prove the authenticated privileged seam end-to-end for **`GetStatus` + `EngageKillSwitch` +
`ReleaseKillSwitch`**, with everything §3–§8 demands, tested on Linux against a mock enforcer, plus
the crash-recovery test. The Windows-only edges (real firewall, ProgramData ACL, named-pipe SID)
are `#[cfg(windows)]` and cross-checked, not run here — stated honestly per `RUNBOOK_WINDOWS.md`.

**Scope:**
1. **[MODIFY] `ssk-boundary`:** add `KillSwitch::rehydrate(session, scope, policy, state, receipt,
   ledger)` — a validated constructor (runs `verify_audit` on the rehydrated ledger; rejects an
   inconsistent chain) so the broker can restore after a crash and `release` with the persisted
   receipt.
2. **[NEW] `ssk-netd-helper`:** `#![forbid(unsafe_code)]`.
   - `CommandEnvelope`/`Command`/`BrokerResponse` with `#[serde(deny_unknown_fields)]`.
   - The broker: op-lock, nonce set, idempotency map, `expected_state_version`, command-auth.
   - `ReceiptStore` trait + `FileReceiptStore` (atomic write; ProgramData path on Windows behind
     `#[cfg(windows)]`; injected dir otherwise) + the hash-chained on-disk journal.
   - `KillSwitchStatus` + `recover()`/reconcile (§4).
   - Verbs `GetStatus`, `EngageKillSwitch`, `ReleaseKillSwitch` with the §6 contract.
3. **Tests (Linux, mock `BoundaryEnforcer`):** command-auth reject on bad token; nonce replay
   reject; oversized/strict-CBOR reject; op-lock serialization; idempotent retry (single OS effect);
   `expected_state_version` stale reject; engage persists a durable receipt and yields authoritative
   `Engaged`; release consumes it → `Released`, audit re-verified; engage-failure rollback leaves no
   state; **crash-recovery: engage → drop broker (keep store) → `recover()` → `Engaged` with the
   persisted receipt → release succeeds**; reconcile alarm when the store says Engaged but the mock
   enforcer reports the rule absent → `Inconsistent`.

**Out of P0 (later phases):** the Windows named-pipe SID transport wiring end-to-end on a real box,
the `ssk-tauri-bridge` crate + frontend, the service-lifecycle verbs, live capture/events,
packaging/signing. P0 is the security core they all sit on.

**Definition of done for P0:** `cargo build/test` green on Linux for the portable core + mock;
`cargo check --target x86_64-pc-windows-msvc` green for the `#[cfg(windows)]` edges; `fmt` + `clippy
-D warnings` clean; committed with the crash-recovery test named and passing.
