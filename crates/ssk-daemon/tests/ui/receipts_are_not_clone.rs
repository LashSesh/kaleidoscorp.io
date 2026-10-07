// A proof that can be copied can be spent twice: one `ResultReceipt` would
// authorise any number of flows.
use ssk_daemon::ingress::audit::writer::{ArmReceipt, PendingReceipt, ResultReceipt};

fn needs_clone<T: Clone>() {}

fn main() {
    needs_clone::<PendingReceipt>();
    needs_clone::<ResultReceipt>();
    needs_clone::<ArmReceipt>();
}
