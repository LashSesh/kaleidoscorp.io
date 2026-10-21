// `ResultProof` is what the SOCKS5 success reply and the pump demand. It is
// sealed: a type of another crate cannot join it, so the only proof is a durable
// `Connected` result.
use ssk_daemon::ingress::types::ResultProof;

struct Mine;

impl ResultProof for Mine {}

fn main() {}
