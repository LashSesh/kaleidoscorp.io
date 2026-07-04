#![forbid(unsafe_code)]

use ssk_types::{digest_of, Digest, HashAlg, TraceRecord};

pub fn chain_trace(
    prev: &Digest,
    mut trace: TraceRecord,
) -> Result<TraceRecord, ssk_types::TypeError> {
    trace.prev_hash = *prev;
    trace.entry_hash = digest_of(&trace, HashAlg::Blake3)?;
    Ok(trace)
}
