use ssk_core::connection::{Connection, ConnectionInner, CoreCanonicalizer, GateVector, Intent, Policy};

fn main() {
    let c = Connection::<Intent>::new(ConnectionInner::default());
    let c = c.canonicalize(&CoreCanonicalizer).expect("canonicalize");
    // `Connection<Canonical>` has no `gate` method — only `Connection<Placed>`
    // does (Master Spec Ω+1 ch. 3.3's typestate guarantee: `birefract` and
    // `place` cannot be skipped). This must fail to compile.
    let _ = c.gate(&GateVector, &Policy);
}
