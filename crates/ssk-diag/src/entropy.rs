//! The OS-CSPRNG health probe.
//!
//! # What this replaces
//!
//! Both `sskd`'s `run_doctor_checks` and `ssk doctor`'s `check_entropy` opened
//! `/dev/urandom` unconditionally, so the check was `ok: false` on every Windows
//! machine that has ever run it — the *same* defect, in two places, because the
//! logic had been duplicated. P2 fixed both copies and left them duplicated;
//! this module is the single implementation, which is the only version of the
//! fix that a third binary cannot silently miss.
//!
//! # No FFI, and specifically not `BCryptGenRandom`
//!
//! `getrandom` 0.3 calls `ProcessPrng` (`bcryptprimitives.dll`) on Windows —
//! the documented, non-deprecated successor to both `RtlGenRandom` and
//! `BCryptGenRandom` — and `getrandom(2)` on Linux. Binding `BCryptGenRandom`
//! in `ssk-winhost` would add `unsafe` to do what an already-linked, audited
//! crate does, would still leave the Linux path needing a second
//! implementation, and would be the *wrong* API. Nothing about entropy belongs
//! in the FFI crate, which is why this crate is `#![forbid(unsafe_code)]` like
//! every crate in the workspace except `ssk-winhost`.
//!
//! # What a meaningful check asserts — and the trap it avoids
//!
//! The Windows OS CSPRNG never blocks and has no "not yet seeded" state to
//! report, so a check built only on *"the call returned `Ok`"* is close to a
//! tautology: exactly the always-green check that makes a health report
//! worthless. Four things are asserted, each with a real, nameable failure
//! mode:
//!
//! 1. **Availability** — the draw returns `Ok`. Fails when
//!    `bcryptprimitives.dll` is blocked or hooked by EDR or a Defender ASR
//!    rule, on Server Core or in an AppContainer where the provider is
//!    unreachable, or on Linux when `getrandom(2)` returns `ENOSYS`/`EAGAIN`
//!    in a constrained container.
//! 2. **Non-degeneracy** — 32 bytes are not one repeated byte. This is the
//!    realistic Windows compromise (a hooked or stubbed provider returning a
//!    constant buffer) and it is invisible to a success-only check.
//! 3. **Independence across draws** — two *separate* 32-byte draws differ.
//!    Catches a provider seeded once that replays, and any deterministic test
//!    shim that leaked into a release build.
//! 4. **Latency bound** — both draws complete inside
//!    [`LATENCY_BUDGET`]. Microseconds on Windows; the bound catches a
//!    blocking or remotely-backed provider, and on Linux early-boot
//!    `getrandom` blocking.
//!
//! **What it explicitly does not assert:** this is a sanity probe, not a
//! statistical randomness test. 64 bytes cannot support an entropy estimate,
//! and a NIST SP 800-22-style suite would pass for a compromised-but-well-formed
//! generator anyway. The `detail` string says so, so no operator reads more
//! into a green than is there.
//!
//! # False-positive budget
//!
//! P(32 bytes all equal) = 256·2⁻²⁵⁶; P(two 32-byte draws collide) = 2⁻²⁵⁶. A
//! failure here is a real failure, which is what makes failing closed on it
//! defensible rather than flaky.

use std::time::{Duration, Instant};

/// Bytes per draw.
pub const DRAW_LEN: usize = 32;

/// Both draws must complete within this.
pub const LATENCY_BUDGET: Duration = Duration::from_millis(250);

/// An injectable entropy source. The probe takes one so every failure branch
/// is reachable from a test — without this seam all four assertions are
/// unfalsifiable and the check is decoration.
pub type Fill<'a> = &'a mut dyn FnMut(&mut [u8]) -> Result<(), String>;

/// The outcome of one probe.
///
/// `next_step` is `None` on success: an operator instruction that is printed
/// when nothing is wrong is noise. A caller whose report schema requires a
/// string supplies its own "no action" wording.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntropyProbe {
    pub ok: bool,
    pub detail: String,
    pub next_step: Option<String>,
}

/// The provider name this build actually calls, for the `detail` string.
#[must_use]
pub fn provider_name() -> &'static str {
    if cfg!(windows) {
        "ProcessPrng (bcryptprimitives.dll)"
    } else {
        "getrandom(2)"
    }
}

/// Probe the real OS CSPRNG.
#[must_use]
pub fn probe() -> EntropyProbe {
    probe_with(&mut |buf| getrandom::fill(buf).map_err(|err| err.to_string()))
}

/// Probe `fill`, applying all four assertions.
#[must_use]
pub fn probe_with(fill: Fill<'_>) -> EntropyProbe {
    let mut first = [0u8; DRAW_LEN];
    let mut second = [0u8; DRAW_LEN];

    let started = Instant::now();
    if let Err(err) = fill(&mut first) {
        return failed(format!(
            "the OS CSPRNG ({}) refused the first {DRAW_LEN}-byte draw: {err}",
            provider_name()
        ));
    }
    if let Err(err) = fill(&mut second) {
        return failed(format!(
            "the OS CSPRNG ({}) refused the second {DRAW_LEN}-byte draw: {err}",
            provider_name()
        ));
    }
    let elapsed = started.elapsed();

    if let Some(byte) = constant_byte(&first) {
        return failed(format!(
            "the OS CSPRNG ({}) returned {DRAW_LEN} copies of 0x{byte:02x}: the provider is \
             stubbed or hooked, not seeded",
            provider_name()
        ));
    }
    if let Some(byte) = constant_byte(&second) {
        return failed(format!(
            "the OS CSPRNG ({}) returned {DRAW_LEN} copies of 0x{byte:02x} on the second draw",
            provider_name()
        ));
    }
    if first == second {
        return failed(format!(
            "two independent {DRAW_LEN}-byte draws from the OS CSPRNG ({}) were identical: the \
             provider is replaying, not generating",
            provider_name()
        ));
    }
    if elapsed > LATENCY_BUDGET {
        return failed(format!(
            "two {DRAW_LEN}-byte draws from the OS CSPRNG ({}) took {elapsed:?}, over the \
             {LATENCY_BUDGET:?} budget: the provider is blocking or remotely backed",
            provider_name()
        ));
    }

    EntropyProbe {
        ok: true,
        detail: format!(
            "{DRAW_LEN} bytes x 2 from the OS CSPRNG ({}) in {elapsed:?}; draws differ; neither \
             is a constant byte. This is a sanity probe, not a statistical randomness test.",
            provider_name()
        ),
        next_step: None,
    }
}

fn failed(detail: String) -> EntropyProbe {
    EntropyProbe {
        ok: false,
        detail,
        next_step: Some(
            "Verify the OS entropy provider is reachable: on Windows check that \
             bcryptprimitives.dll is not blocked by EDR or a Defender ASR rule; on Linux check \
             that getrandom(2) is permitted by the container's seccomp policy."
                .to_owned(),
        ),
    }
}

/// `Some(b)` when every byte of `buf` is `b`. An empty buffer is not constant
/// in any useful sense and returns `None`.
fn constant_byte(buf: &[u8]) -> Option<u8> {
    let first = *buf.first()?;
    buf.iter().all(|b| *b == first).then_some(first)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A source that hands out a fresh counter-derived buffer each call, so it
    /// is available, non-constant and non-repeating.
    fn healthy() -> impl FnMut(&mut [u8]) -> Result<(), String> {
        let mut call = 0u8;
        move |buf| {
            call = call.wrapping_add(1);
            for (i, b) in buf.iter_mut().enumerate() {
                *b = u8::try_from(i % 256)
                    .unwrap_or(0)
                    .wrapping_mul(7)
                    .wrapping_add(call);
            }
            Ok(())
        }
    }

    #[test]
    fn the_real_os_csprng_is_healthy_on_this_machine() {
        // Asserts the *machine*, which is why the injected tests below exist:
        // they assert the *code* can still say no.
        let probe = probe();
        assert!(probe.ok, "{}", probe.detail);
        assert!(probe.next_step.is_none());
        assert!(
            probe.detail.contains("sanity probe, not a statistical"),
            "the detail string must not overclaim: {}",
            probe.detail
        );
    }

    #[test]
    fn the_probe_never_names_dev_urandom() {
        // The exact regression: `/dev/urandom` does not exist on Windows, and
        // naming it in the report was how a machine-independent defect got
        // reported as a machine problem.
        let probe = probe();
        assert!(!probe.detail.contains("/dev/urandom"), "{}", probe.detail);
    }

    #[test]
    fn the_provider_named_is_the_one_this_build_calls() {
        if cfg!(windows) {
            assert_eq!(provider_name(), "ProcessPrng (bcryptprimitives.dll)");
        } else {
            assert_eq!(provider_name(), "getrandom(2)");
        }
        assert!(probe().detail.contains(provider_name()));
    }

    #[test]
    fn a_healthy_injected_source_passes() {
        let mut source = healthy();
        let probe = probe_with(&mut source);
        assert!(probe.ok, "{}", probe.detail);
    }

    #[test]
    fn an_unavailable_provider_fails_closed() {
        let mut source = |_: &mut [u8]| Err("ENOSYS".to_owned());
        let probe = probe_with(&mut source);
        assert!(!probe.ok);
        assert!(probe.detail.contains("ENOSYS"), "{}", probe.detail);
        assert!(probe.next_step.is_some());
    }

    #[test]
    fn a_provider_that_fails_only_on_the_second_draw_fails_closed() {
        let mut calls = 0u32;
        let mut source = move |buf: &mut [u8]| {
            calls += 1;
            if calls == 1 {
                buf.copy_from_slice(&[7u8; DRAW_LEN]);
                Ok(())
            } else {
                Err("EAGAIN".to_owned())
            }
        };
        let probe = probe_with(&mut source);
        assert!(!probe.ok);
        assert!(probe.detail.contains("second"), "{}", probe.detail);
    }

    #[test]
    fn an_all_zero_buffer_fails_closed() {
        // The classic stubbed provider. A success-only check calls this green,
        // and the pre-P2 check only tested 8 bytes for all-zero.
        let mut source = |buf: &mut [u8]| {
            buf.fill(0);
            Ok(())
        };
        let probe = probe_with(&mut source);
        assert!(!probe.ok);
        assert!(probe.detail.contains("0x00"), "{}", probe.detail);
    }

    #[test]
    fn an_all_ones_buffer_fails_closed() {
        let mut source = |buf: &mut [u8]| {
            buf.fill(0xff);
            Ok(())
        };
        let probe = probe_with(&mut source);
        assert!(!probe.ok);
        assert!(probe.detail.contains("0xff"), "{}", probe.detail);
    }

    #[test]
    fn any_constant_byte_fails_closed_not_just_zero_and_ff() {
        for value in [0x01u8, 0x5a, 0xaa] {
            let mut source = move |buf: &mut [u8]| {
                buf.fill(value);
                Ok(())
            };
            let probe = probe_with(&mut source);
            assert!(!probe.ok, "0x{value:02x} must be rejected");
        }
    }

    #[test]
    fn a_replaying_provider_fails_closed() {
        // Non-constant, always available — and still broken. Only the
        // independence assertion catches this one.
        let mut source = |buf: &mut [u8]| {
            for (i, b) in buf.iter_mut().enumerate() {
                *b = u8::try_from(i % 256).unwrap_or(0);
            }
            Ok(())
        };
        let probe = probe_with(&mut source);
        assert!(!probe.ok);
        assert!(probe.detail.contains("replaying"), "{}", probe.detail);
    }

    #[test]
    fn a_provider_slower_than_the_budget_fails_closed() {
        let mut source = healthy();
        let mut slow = move |buf: &mut [u8]| {
            std::thread::sleep(LATENCY_BUDGET / 2 + Duration::from_millis(20));
            source(buf)
        };
        let probe = probe_with(&mut slow);
        assert!(!probe.ok);
        assert!(probe.detail.contains("budget"), "{}", probe.detail);
    }

    #[test]
    fn constant_byte_is_exact() {
        assert_eq!(constant_byte(&[]), None);
        assert_eq!(constant_byte(&[9]), Some(9));
        assert_eq!(constant_byte(&[9, 9, 9]), Some(9));
        assert_eq!(constant_byte(&[9, 9, 8]), None);
    }
}
