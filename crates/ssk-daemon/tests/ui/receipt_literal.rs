// A receipt cannot be written out as a struct literal: its fields are private, so
// no code outside the audit writer can claim that a record is durable.
use ssk_daemon::ingress::audit::writer::Receipt;

fn main() {
    let _ = Receipt {
        seq: 1,
        entry_hash: String::new(),
    };
}
