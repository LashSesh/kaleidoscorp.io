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

pub mod target;
pub mod types;

/// `Ipv6Addr::to_ipv4()` maps `::1` to 0.0.0.1 and `::` to 0.0.0.0, i.e. it
/// turns an IPv6 address into a different IPv4 one. Only the strict
/// `to_ipv4_mapped()` (`::ffff:a.b.c.d`) may be used anywhere in the ingress
/// (design 6.2), and this scan makes that a test and not a convention.
#[cfg(test)]
mod source_scan {
    use std::path::{Path, PathBuf};

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
    fn the_lossy_ipv6_to_ipv4_conversion_is_never_used_in_the_ingress() {
        // Built from two halves so that this file does not contain the needle.
        let needle = concat!(".to_ipv", "4(");
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/ingress");
        let mut files = Vec::new();
        rust_files(&root, &mut files);
        assert!(
            files.len() >= 2,
            "the scan must see the ingress tree, saw {files:?}"
        );
        let offenders: Vec<_> = files
            .iter()
            .filter(|path| {
                std::fs::read_to_string(path)
                    .expect("read an ingress source file")
                    .contains(needle)
            })
            .collect();
        assert!(
            offenders.is_empty(),
            "Ipv6Addr::to_ipv4 turns ::1 into 0.0.0.1; use to_ipv4_mapped: {offenders:?}"
        );
    }

    #[test]
    fn the_scan_would_notice_the_needle() {
        // A scan that cannot fail proves nothing: check the needle against a
        // line that really contains the call.
        let line = format!("let v4 = addr{}", concat!(".to_ipv", "4();"));
        assert!(line.contains(concat!(".to_ipv", "4(")));
    }
}
