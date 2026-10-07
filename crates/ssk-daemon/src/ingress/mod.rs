// The local proxy ingress (design: docs/M2_LOCAL_INGRESS_DESIGN.md).
//
// Everything under this module faces hostile input (any local process can
// reach a loopback port) and the release profile has `overflow-checks = true`,
// so an unchecked `+`, an index or an `unwrap` here is a panic, and three flow
// panics trip the whole ingress. The set below turns those into compile errors
// for production code (design 12.12). `cfg_attr(not(test), ..)` keeps the
// repository's usual `expect`-heavy tests compiling.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic,
        clippy::todo,
        clippy::unimplemented,
        clippy::unreachable,
        clippy::arithmetic_side_effects,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_possible_wrap
    )
)]

pub mod budget;
pub mod limits;
pub mod pump;
pub mod socks5;
pub mod target;
pub mod types;

/// The std conversion of an IPv6 address to IPv4 that is not the strict mapped
/// one answers 0.0.0.1 for `::1` and 0.0.0.0 for `::`, i.e. it turns an IPv6
/// address into a different IPv4 one. Only `to_ipv4_mapped` (`::ffff:a.b.c.d`)
/// may be used anywhere in the ingress (design 6.2), and this scan makes that a
/// test and not a convention. It reads every source file of `src/ingress`,
/// comments and tests included, in every call form.
#[cfg(test)]
mod source_scan {
    use std::path::{Path, PathBuf};

    /// Built from two halves so that this file does not contain the needle.
    const LOSSY: &str = concat!("to_ipv", "4");
    /// What may follow the needle: the strict conversion.
    const STRICT_SUFFIX: &str = "_mapped";

    /// `true` when `source` names the lossy conversion anywhere: the needle
    /// followed by anything but the strict suffix. Plain substring matching, so
    /// a method call, a path call, a path used as a function value, a call
    /// split over lines and a mention in a comment are all found.
    fn offends(source: &str) -> bool {
        source.match_indices(LOSSY).any(|(at, _)| {
            !source
                .get(at + LOSSY.len()..)
                .is_some_and(|rest| rest.starts_with(STRICT_SUFFIX))
        })
    }

    fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
        let entries = std::fs::read_dir(dir).expect("read the ingress source directory");
        for entry in entries {
            let path = entry.expect("directory entry").path();
            if path.is_dir() {
                rust_files(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
    }

    #[test]
    fn the_lossy_ipv6_to_v4_conversion_is_never_used_in_the_ingress() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/ingress");
        let mut files = Vec::new();
        rust_files(&root, &mut files);
        assert!(
            files.len() >= 4,
            "the scan must see the ingress tree, saw {files:?}"
        );
        let offenders: Vec<_> = files
            .iter()
            .filter(|path| offends(&std::fs::read_to_string(path).expect("read a source file")))
            .collect();
        assert!(
            offenders.is_empty(),
            "the lossy conversion turns ::1 into 0.0.0.1; use the strict mapped one: {offenders:?}"
        );
    }

    #[test]
    fn the_scan_notices_every_call_form() {
        for source in [
            format!("let v4 = addr.{LOSSY}();"),
            format!("let v4 = Ipv6Addr::{LOSSY}(addr);"),
            format!("addrs.iter().map(Ipv6Addr::{LOSSY})"),
            format!("let v4 = addr\n    .{LOSSY} ();"),
            format!("// addr.{LOSSY}() is wrong"),
            format!("addr.{LOSSY}_other()"),
        ] {
            assert!(offends(&source), "{source}");
        }
    }

    #[test]
    fn the_scan_accepts_the_strict_conversion_and_unrelated_text() {
        for source in [
            format!("let v4 = addr.{LOSSY}_mapped();"),
            format!("Ipv6Addr::{LOSSY}_mapped(&addr)"),
            format!("addr\n    .{LOSSY}_mapped ()"),
            "let ip = addr.to_string();".to_owned(),
            String::new(),
        ] {
            assert!(!offends(&source), "{source}");
        }
        // A needle at the very end of the text, with nothing after it, offends.
        assert!(offends(LOSSY));
    }
}
