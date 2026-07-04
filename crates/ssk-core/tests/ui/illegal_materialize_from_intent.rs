use ssk_core::connection::{Connection, ConnectionInner, Intent};

fn main() {
    let c = Connection::<Intent>::new(make_inner());
    // `Connection<Intent>` has no `materialize` method — only
    // `Connection<GatePassed>` does (Master Spec Ω+1 ch. 3.3's typestate
    // guarantee). This must fail to compile.
    let _ = c.materialize(&mut ());
}

fn make_inner() -> ConnectionInner {
    unimplemented!()
}
