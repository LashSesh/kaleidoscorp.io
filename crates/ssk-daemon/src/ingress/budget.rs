//! The descriptor budget (design 7.3): how many tunnels the process may hold
//! open without starving the IPC server and the daemon itself.
//!
//! An IPC `accept()` that fails 60 times in a row ends the daemon (8.6), and
//! the ingress is the one component that opens descriptors on behalf of any
//! local process. So the ingress adapts to the limit the process was given
//! (it never calls `setrlimit`, which is process-wide state) and refuses to
//! serve when the limit cannot pay for even a handful of tunnels.
//!
//! Pure arithmetic plus one syscall shim. The numbers are a bound by
//! construction, not a measurement; only [`FD_RESERVE`] is backed by one, and
//! `tests/fd_baseline.rs` re-measures it against a real `sskd`.

use std::time::Duration;

use super::types::IngressLimits;

/// The process baseline plus a saturated IPC server. Measured maximum: 29
/// (idle `sskd` 12; 16 IPC clients 28; a 17th connection waiting for a permit
/// 29). The margin covers `audit.json`, crash records and a second log file at
/// rotation.
pub const FD_RESERVE: u64 = 64;
/// Every socket from accept until its handshake is done (peer check and
/// handshake): `Tuning::pre_admission_slots`.
pub const PRE_ADMISSION_FDS: u64 = 64;
/// The peer service's table reads (`/proc/net/tcp`, `/proc/net/tcp6`).
pub const PEER_TABLE_FDS: u64 = 2;
/// In-flight name resolutions (`ssk_netcore::MAX_CONCURRENT_LOOKUPS`), each up
/// to three descriptors (UDP socket, hosts file, resolver configuration).
pub const LOOKUP_FDS: u64 = 48;
/// Extra racing dial attempts (`ssk_netcore::DIAL_EXTRA_PERMITS`).
pub const DIAL_EXTRA_FDS: u64 = 64;
/// Sockets waiting for a permit (`Tuning::capacity_wait_room`).
pub const CAPACITY_WAIT_FDS: u64 = 8;
/// Listener 1, shed-and-close transient 1, ledger 4 (directory fd, active
/// segment, next segment during rotation, state-root fd at open).
pub const LISTENER_AND_LEDGER_FDS: u64 = 6;
/// Descriptors per lookup in [`LOOKUP_FDS`].
pub const FDS_PER_LOOKUP: u64 = 3;
/// Descriptors per open tunnel: the client socket and the upstream socket.
pub const FDS_PER_TUNNEL: u64 = 2;

/// Everything that is not an open tunnel, the reserve included.
pub const FD_FIXED: u64 = 256;

/// Below this many connections the limit pays for no useful ingress and the
/// start is refused with `INGRESS_FD_LIMIT_TOO_LOW`.
pub const MIN_FD_CONNECTIONS: u32 = 8;

/// The result of fitting the configured connection limit into the process's
/// descriptor limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FdBudget {
    /// The soft `RLIMIT_NOFILE`; `None` when there is no limit to apply
    /// (unlimited, or a platform without the concept).
    pub soft: Option<u64>,
    /// `limits.max_connections` as configured.
    pub configured: u32,
    /// What the semaphore may hold: the configured value, or fewer when the
    /// limit does not pay for it.
    pub effective_max_connections: u32,
    /// Descriptors the CONFIGURED value needs: `FD_FIXED + 2 * configured`.
    pub needed: u64,
    /// `effective_max_connections < configured`.
    pub clamped: bool,
    /// The limit cannot pay for [`MIN_FD_CONNECTIONS`] tunnels. When this is
    /// set, `effective_max_connections` is only what would have been possible
    /// and no listener may be started.
    pub too_low: bool,
}

/// Descriptors needed for `connections` open tunnels.
#[must_use]
pub fn fd_needed(connections: u32) -> u64 {
    u64::from(connections)
        .saturating_mul(FDS_PER_TUNNEL)
        .saturating_add(FD_FIXED)
}

/// Fits `configured` tunnels into `soft` descriptors:
///
/// ```text
/// cap                       = floor((soft - 256) / 2)      (0 below 256)
/// effective_max_connections = min(configured, cap)
/// too_low                   = soft is Some and cap < 8     (soft < 272)
/// ```
///
/// `configured` is validated by `ssk-config` to be at least 1; a 0 here would
/// give a semaphore with no permits, which refuses everything and is the safe
/// reading of a broken input.
#[must_use]
pub fn fd_budget(soft: Option<u64>, configured: u32) -> FdBudget {
    let needed = fd_needed(configured);
    let Some(limit) = soft else {
        return FdBudget {
            soft,
            configured,
            effective_max_connections: configured,
            needed,
            clamped: false,
            too_low: false,
        };
    };
    let cap = limit.saturating_sub(FD_FIXED) / FDS_PER_TUNNEL;
    let cap = u32::try_from(cap).unwrap_or(u32::MAX);
    let effective = configured.min(cap);
    FdBudget {
        soft,
        configured,
        effective_max_connections: effective,
        needed,
        clamped: effective < configured,
        too_low: cap < MIN_FD_CONNECTIONS,
    }
}

/// The soft limit out of the kernel's answer. `None` is "unlimited".
#[cfg(unix)]
fn soft_of(limit: rustix::process::Rlimit) -> Option<u64> {
    limit.current
}

/// The process's soft `RLIMIT_NOFILE`, or `None` when it is unlimited. The
/// limit is never raised here.
#[cfg(unix)]
#[must_use]
pub fn soft_fd_limit() -> Option<u64> {
    soft_of(rustix::process::getrlimit(
        rustix::process::Resource::Nofile,
    ))
}

/// Windows has no `RLIMIT_NOFILE`. UNVERIFIED that Windows handle limits never
/// bind at the numbers used here (design 7.3).
#[cfg(not(unix))]
#[must_use]
pub fn soft_fd_limit() -> Option<u64> {
    None
}

/// The configured limits after the descriptor budget has been applied (step 3
/// of the start task). Defined here rather than in `types.rs` because it holds
/// an [`FdBudget`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedLimits {
    /// Effective, never more than configured.
    pub max_connections: u32,
    pub accept_rate_per_s: u32,
    pub handshake: Duration,
    pub connect: Duration,
    pub idle: Duration,
    pub fd: FdBudget,
}

impl ResolvedLimits {
    #[must_use]
    pub fn resolve(limits: &IngressLimits, soft: Option<u64>) -> Self {
        let fd = fd_budget(soft, limits.max_connections);
        Self {
            max_connections: fd.effective_max_connections,
            accept_rate_per_s: limits.accept_rate_per_s,
            handshake: Duration::from_millis(u64::from(limits.handshake_timeout_ms)),
            connect: Duration::from_millis(u64::from(limits.connect_timeout_ms)),
            idle: Duration::from_millis(u64::from(limits.idle_timeout_ms)),
            fd,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingress::types::Tuning;
    use proptest::prelude::*;

    #[test]
    fn fixed_total_is_the_sum_of_components_that_come_from_the_code() {
        let tuning = Tuning::default();
        // Each component is the real constant of the component that spends the
        // descriptors, so raising one of them fails here until the budget is
        // revisited.
        let pre_admission = u64::try_from(tuning.pre_admission_slots).expect("fits");
        let lookups = u64::try_from(ssk_netcore::MAX_CONCURRENT_LOOKUPS).expect("fits");
        let racing = u64::try_from(ssk_netcore::DIAL_EXTRA_PERMITS).expect("fits");
        let waiting = u64::try_from(tuning.capacity_wait_room).expect("fits");
        assert_eq!(PRE_ADMISSION_FDS, pre_admission);
        assert_eq!(LOOKUP_FDS, lookups * FDS_PER_LOOKUP);
        assert_eq!(DIAL_EXTRA_FDS, racing);
        assert_eq!(CAPACITY_WAIT_FDS, waiting);
        assert_eq!(
            FD_RESERVE
                + PRE_ADMISSION_FDS
                + PEER_TABLE_FDS
                + LOOKUP_FDS
                + DIAL_EXTRA_FDS
                + CAPACITY_WAIT_FDS
                + LISTENER_AND_LEDGER_FDS,
            FD_FIXED
        );
        assert_eq!(FD_FIXED, 256);
    }

    #[test]
    fn the_reserve_is_well_above_the_measured_baseline_of_a_saturated_ipc_server() {
        // 29 = 12 idle + 16 IPC connections + the 17th waiting for a permit.
        let measured = 29;
        assert!(FD_RESERVE >= 2 * measured, "margin of about 2.2x");
    }

    #[test]
    fn fd_needed_is_fixed_plus_two_per_tunnel() {
        assert_eq!(fd_needed(0), 256);
        assert_eq!(fd_needed(1), 258);
        assert_eq!(fd_needed(256), 768);
        assert_eq!(fd_needed(u32::MAX), 256 + 2 * u64::from(u32::MAX));
    }

    /// `(soft, configured) -> (effective, clamped, too_low)`; computed by hand
    /// from `cap = floor((soft - 256) / 2)`.
    #[test]
    fn fd_budget_table() {
        let none = None;
        // (soft, [(configured, effective, clamped, too_low)])
        type Row = (Option<u64>, [(u32, u32, bool, bool); 4]);
        let table: [Row; 11] = [
            (
                none,
                [
                    (1, 1, false, false),
                    (64, 64, false, false),
                    (256, 256, false, false),
                    (4096, 4096, false, false),
                ],
            ),
            (
                Some(0),
                [
                    (1, 0, true, true),
                    (64, 0, true, true),
                    (256, 0, true, true),
                    (4096, 0, true, true),
                ],
            ),
            (
                Some(255),
                [
                    (1, 0, true, true),
                    (64, 0, true, true),
                    (256, 0, true, true),
                    (4096, 0, true, true),
                ],
            ),
            (
                Some(256),
                [
                    (1, 0, true, true),
                    (64, 0, true, true),
                    (256, 0, true, true),
                    (4096, 0, true, true),
                ],
            ),
            // cap 7: one short of usable.
            (
                Some(271),
                [
                    (1, 1, false, true),
                    (64, 7, true, true),
                    (256, 7, true, true),
                    (4096, 7, true, true),
                ],
            ),
            // cap 8: the smallest usable limit.
            (
                Some(272),
                [
                    (1, 1, false, false),
                    (64, 8, true, false),
                    (256, 8, true, false),
                    (4096, 8, true, false),
                ],
            ),
            // cap 72.
            (
                Some(400),
                [
                    (1, 1, false, false),
                    (64, 64, false, false),
                    (256, 72, true, false),
                    (4096, 72, true, false),
                ],
            ),
            // The default of 256 fits and needs 768.
            (
                Some(1024),
                [
                    (1, 1, false, false),
                    (64, 64, false, false),
                    (256, 256, false, false),
                    (4096, 384, true, false),
                ],
            ),
            (
                Some(4096),
                [
                    (1, 1, false, false),
                    (64, 64, false, false),
                    (256, 256, false, false),
                    (4096, 1920, true, false),
                ],
            ),
            (
                Some(20_000),
                [
                    (1, 1, false, false),
                    (64, 64, false, false),
                    (256, 256, false, false),
                    (4096, 4096, false, false),
                ],
            ),
            (
                Some(u64::MAX),
                [
                    (1, 1, false, false),
                    (64, 64, false, false),
                    (256, 256, false, false),
                    (4096, 4096, false, false),
                ],
            ),
        ];
        for (soft, rows) in table {
            for (configured, effective, clamped, too_low) in rows {
                let budget = fd_budget(soft, configured);
                let ctx = format!("soft {soft:?}, configured {configured}");
                assert_eq!(budget.effective_max_connections, effective, "{ctx}");
                assert_eq!(budget.clamped, clamped, "{ctx}");
                assert_eq!(budget.too_low, too_low, "{ctx}");
                assert_eq!(budget.soft, soft, "{ctx}");
                assert_eq!(budget.configured, configured, "{ctx}");
                assert_eq!(budget.needed, fd_needed(configured), "{ctx}");
            }
        }
    }

    #[test]
    fn a_small_configuration_is_not_refused_just_because_it_is_small() {
        // `effective < 8` alone would make `max_connections: 4` unavailable on a
        // machine with plenty of descriptors; the refusal is about the limit.
        let budget = fd_budget(Some(65_536), 4);
        assert_eq!(budget.effective_max_connections, 4);
        assert!(!budget.too_low && !budget.clamped);
    }

    proptest! {
        #[test]
        fn the_effective_limit_is_the_largest_one_the_descriptors_pay_for(
            soft in 0_u64..200_000,
            configured in 1_u32..=4096,
        ) {
            let budget = fd_budget(Some(soft), configured);
            let effective = u64::from(budget.effective_max_connections);
            prop_assert!(budget.effective_max_connections <= configured);
            prop_assert_eq!(budget.clamped, budget.effective_max_connections < configured);
            if soft >= FD_FIXED {
                // What is allowed is paid for ...
                prop_assert!(FD_FIXED + 2 * effective <= soft);
                // ... and a clamped value is maximal: one more would not fit.
                if budget.clamped {
                    prop_assert!(FD_FIXED + 2 * (effective + 1) > soft);
                }
            } else {
                prop_assert_eq!(budget.effective_max_connections, 0);
            }
            prop_assert_eq!(
                budget.too_low,
                soft < FD_FIXED + 2 * u64::from(MIN_FD_CONNECTIONS)
            );
        }

        #[test]
        fn no_limit_means_no_clamp(configured in 1_u32..=u32::MAX) {
            let budget = fd_budget(None, configured);
            prop_assert_eq!(budget.effective_max_connections, configured);
            prop_assert!(!budget.clamped && !budget.too_low);
        }
    }

    #[test]
    fn resolved_limits_apply_the_budget_and_convert_the_timeouts() {
        let limits = IngressLimits::default();
        let roomy = ResolvedLimits::resolve(&limits, Some(20_000));
        assert_eq!(roomy.max_connections, limits.max_connections);
        assert_eq!(roomy.accept_rate_per_s, limits.accept_rate_per_s);
        assert_eq!(
            roomy.handshake,
            Duration::from_millis(u64::from(limits.handshake_timeout_ms))
        );
        assert_eq!(
            roomy.connect,
            Duration::from_millis(u64::from(limits.connect_timeout_ms))
        );
        assert_eq!(
            roomy.idle,
            Duration::from_millis(u64::from(limits.idle_timeout_ms))
        );
        assert!(!roomy.fd.clamped);

        let tight = ResolvedLimits::resolve(&limits, Some(400));
        assert_eq!(tight.max_connections, 72);
        assert_eq!(tight.fd.configured, limits.max_connections);
        assert!(tight.fd.clamped && !tight.fd.too_low);
        // The three timeouts are three different fields.
        let distinct = IngressLimits {
            handshake_timeout_ms: 1_111,
            connect_timeout_ms: 2_222,
            idle_timeout_ms: 3_333,
            ..IngressLimits::default()
        };
        let resolved = ResolvedLimits::resolve(&distinct, None);
        assert_eq!(
            (resolved.handshake, resolved.connect, resolved.idle),
            (
                Duration::from_millis(1_111),
                Duration::from_millis(2_222),
                Duration::from_millis(3_333)
            )
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_shim_reads_the_soft_limit_and_unlimited_is_none() {
        let limit = |current, maximum| rustix::process::Rlimit { current, maximum };
        assert_eq!(soft_of(limit(Some(512), Some(4096))), Some(512));
        assert_eq!(soft_of(limit(Some(512), None)), Some(512));
        assert_eq!(soft_of(limit(None, Some(4096))), None);
        assert_eq!(soft_of(limit(None, None)), None);
    }

    /// The right resource: a child shell inherits this process's limits, and its
    /// `ulimit -Sn` is the soft `RLIMIT_NOFILE` as the kernel reports it.
    #[cfg(unix)]
    #[test]
    fn the_shim_asks_about_open_files() {
        let output = std::process::Command::new("sh")
            .args(["-c", "ulimit -Sn"])
            .output()
            .expect("run sh");
        assert!(output.status.success());
        let text = String::from_utf8(output.stdout).expect("utf-8");
        let expected = match text.trim() {
            "unlimited" => None,
            number => Some(number.parse::<u64>().expect("a number")),
        };
        assert_eq!(soft_fd_limit(), expected);
    }
}
