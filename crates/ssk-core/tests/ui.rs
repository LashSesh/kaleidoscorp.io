//! Compile-fail harness proving the `Connection<S>` typestate (Master Spec
//! Ω+1 ch. 3.3) blocks illegal transitions at compile time, not just at
//! runtime.
//!
//! `trybuild::compile_fail` pins the **exact** `.stderr` snapshot next to each
//! case, so these do *not* float across rustc versions: a rendering change in
//! rustc's diagnostics fails the test until the snapshot is re-blessed with
//! `TRYBUILD=overwrite`. That is deliberate — the snapshot is what asserts the
//! error is `E0599 no method named ... found for struct Connection<WrongState>`
//! and not some unrelated compile error that would satisfy "it failed to
//! compile" while proving nothing. When re-blessing, read the regenerated
//! `.stderr` and confirm the error code, method name and state type are
//! unchanged.

#[test]
fn ui() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/*.rs");
}
