//! The receipts of the flow ledger are proofs, and a proof that can be made by
//! hand proves nothing.
//!
//! `trybuild::compile_fail` pins the exact `.stderr` snapshot next to each case,
//! so these assert the error (private field, private module, unsatisfied sealed
//! bound, missing `Clone`) and not merely that something failed to compile. When
//! the compiler's wording changes, re-bless with `TRYBUILD=overwrite`, read the
//! regenerated `.stderr` and confirm that the error code and the type named in it
//! are unchanged.

#[test]
fn the_receipts_cannot_be_made_cloned_or_imitated_from_outside() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/ui/*.rs");
}
