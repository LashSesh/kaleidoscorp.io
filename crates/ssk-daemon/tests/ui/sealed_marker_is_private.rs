// The marker that seals `ResultProof` cannot be named from outside the crate, so
// it cannot be implemented to get around the seal.
use ssk_daemon::ingress::types::sealed::Sealed;

struct Mine;

impl Sealed for Mine {}

fn main() {}
