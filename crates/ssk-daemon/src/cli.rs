#![forbid(unsafe_code)]

//! `sskd`'s argument surface.
//!
//! Hand-written rather than `clap`-derived: `sskd` accepts three flags, and
//! adding a 100-crate-deep argument parser to a daemon for three flags is not
//! a trade worth making. It is a pure function over an iterator so every
//! branch is testable, which is the property that actually matters here.
//!
//! There is deliberately **no `--force`** — see [`crate::lock`] for why a
//! flag that would let two daemons share one hash-chained audit ledger has
//! strictly negative value.

use std::ffi::OsString;
use std::time::Duration;

pub const USAGE: &str = "\
sskd — the Kaleidoscorp daemon

Usage: sskd [OPTIONS]

Options:
      --lock-wait <MILLISECONDS>  Wait up to this long for the daemon lock, for
                                  the genuine restart race where the previous
                                  process is still tearing down [default: 0]
      --print-lock-holder         Print the current lock holder as JSON and
                                  exit without starting the daemon
  -h, --help                      Print this message

Environment:
  SSK_STATE_DIR   Absolute override for the state directory
  SSK_CONFIG_PATH Path to the daemon config
  SSK_LOG         Log filter (tracing-subscriber EnvFilter syntax)
";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    pub lock_wait: Duration,
    pub print_lock_holder: bool,
    pub help: bool,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            lock_wait: Duration::ZERO,
            print_lock_holder: false,
            help: false,
        }
    }
}

impl Args {
    /// Parse `sskd`'s arguments (the iterator must **not** include argv[0]).
    ///
    /// # Errors
    /// A human-readable message for an unknown flag, a missing value, or a
    /// value that is not a non-negative integer. Unknown flags are rejected
    /// rather than ignored: silently accepting `--fore` when the user meant
    /// something is how a daemon ends up doing the opposite of what was asked.
    pub fn parse<I>(args: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = OsString>,
    {
        let mut parsed = Args::default();
        let mut iter = args.into_iter();
        while let Some(raw) = iter.next() {
            let arg = raw.to_string_lossy().into_owned();
            match arg.as_str() {
                "--help" | "-h" => parsed.help = true,
                "--print-lock-holder" => parsed.print_lock_holder = true,
                "--lock-wait" => {
                    let value = iter.next().ok_or_else(|| {
                        "--lock-wait requires a value in milliseconds".to_string()
                    })?;
                    parsed.lock_wait = parse_millis(&value.to_string_lossy())?;
                }
                other if other.starts_with("--lock-wait=") => {
                    parsed.lock_wait = parse_millis(&other["--lock-wait=".len()..])?;
                }
                other => {
                    return Err(format!("unrecognised argument `{other}`\n\n{USAGE}"));
                }
            }
        }
        Ok(parsed)
    }
}

fn parse_millis(raw: &str) -> Result<Duration, String> {
    raw.parse::<u64>()
        .map(Duration::from_millis)
        .map_err(|err| format!("--lock-wait expects a whole number of milliseconds: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Args, String> {
        Args::parse(args.iter().map(OsString::from))
    }

    #[test]
    fn no_arguments_is_the_default() {
        assert_eq!(parse(&[]).expect("parse"), Args::default());
    }

    #[test]
    fn the_default_lock_wait_is_zero() {
        // Anything else would make the common "another daemon is running"
        // case hang instead of reporting.
        assert_eq!(Args::default().lock_wait, Duration::ZERO);
    }

    #[test]
    fn lock_wait_accepts_both_spellings() {
        assert_eq!(
            parse(&["--lock-wait", "2500"]).expect("parse").lock_wait,
            Duration::from_millis(2500)
        );
        assert_eq!(
            parse(&["--lock-wait=2500"]).expect("parse").lock_wait,
            Duration::from_millis(2500)
        );
    }

    #[test]
    fn lock_wait_without_a_value_is_an_error() {
        assert!(parse(&["--lock-wait"]).is_err());
    }

    #[test]
    fn a_non_numeric_lock_wait_is_an_error_not_a_silent_zero() {
        let err = parse(&["--lock-wait", "soon"]).expect_err("must reject");
        assert!(err.contains("milliseconds"), "{err}");
    }

    #[test]
    fn a_negative_lock_wait_is_an_error() {
        assert!(parse(&["--lock-wait", "-1"]).is_err());
    }

    #[test]
    fn print_lock_holder_is_recognised() {
        assert!(
            parse(&["--print-lock-holder"])
                .expect("parse")
                .print_lock_holder
        );
    }

    #[test]
    fn help_is_recognised_in_both_spellings() {
        assert!(parse(&["--help"]).expect("parse").help);
        assert!(parse(&["-h"]).expect("parse").help);
    }

    #[test]
    fn an_unknown_flag_is_rejected_and_the_usage_is_shown() {
        let err = parse(&["--force"]).expect_err("must reject");
        assert!(err.contains("--force"), "{err}");
        assert!(err.contains("Usage:"), "{err}");
    }

    #[test]
    fn there_is_no_force_flag() {
        // Pinned as a decision, not an oversight: under a kernel-arbitrated
        // lock a failed acquisition always means a live holder, so --force
        // could only ever mean "run two daemons against one audit chain".
        assert!(!USAGE.contains("--force"));
        assert!(parse(&["--force"]).is_err());
    }

    #[test]
    fn flags_compose() {
        let args = parse(&["--lock-wait", "100", "--print-lock-holder"]).expect("parse");
        assert_eq!(args.lock_wait, Duration::from_millis(100));
        assert!(args.print_lock_holder);
    }
}
