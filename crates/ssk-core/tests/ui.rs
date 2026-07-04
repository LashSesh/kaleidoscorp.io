//! Compile-fail harness proving the `Connection<S>` typestate (Master Spec
//! Ω+1 ch. 3.3) blocks illegal transitions at compile time, not just at
//! runtime. Deliberately does not pin an exact `.stderr` snapshot — only that
//! compilation fails — so this stays stable across rustc versions.

#[test]
fn ui() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/*.rs");
}
