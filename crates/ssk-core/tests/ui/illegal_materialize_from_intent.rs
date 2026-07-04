use ssk_core::connection::{Connection, ConnectionInner, Intent, StitchTensor};

fn main() {
    let c = Connection::<Intent>::new(ConnectionInner::default());
    // `Connection<Intent>` has no `materialize` method — only
    // `Connection<GatePassed>` does (Master Spec Ω+1 ch. 3.3's typestate
    // guarantee). This must fail to compile.
    let mut tensor = StitchTensor::default();
    let _ = c.materialize(&mut tensor);
}
