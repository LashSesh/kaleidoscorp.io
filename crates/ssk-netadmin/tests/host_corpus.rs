//! The policy engine against the host corpus it shares with `ssk-config`: a
//! domain suffix must never match a host the config grammar calls an address.

include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/support/host_corpus.rs"
));

use ssk_netadmin::flow::{FlowDescriptor, FlowRecord, ProtocolKind, RiskLevel};
use ssk_netadmin::policy::MatchCriteria;

#[test]
fn host_corpus_agrees_everywhere() {
    let corpus = host_corpus();
    let mut disagreements = Vec::new();
    for case in &corpus {
        // `Malformed` has no promised answer: the engine compares text.
        let Some(address_form) = case.class.address_form() else {
            continue;
        };
        // A suffix equal to the host matches it on a label boundary, so the
        // only thing that can stop it is the address-form test. Going through
        // `matches` keeps the engine's own normalisation (case, trailing dot).
        let criteria = MatchCriteria {
            dest_suffix: Some(case.host.clone()),
            ..MatchCriteria::default()
        };
        let flow = FlowRecord::new(
            "flow-corpus",
            0,
            FlowDescriptor::new("app", &case.host, 443, ProtocolKind::Https, RiskLevel::Low),
        );
        // An address must never be captured by a suffix; a name must be.
        let matched = criteria.matches(&flow);
        if matched == address_form {
            disagreements.push(format!(
                "{:?} ({:?}): suffix rule matched={matched}, expected {}",
                case.host, case.class, !address_form
            ));
        }
    }
    assert!(
        disagreements.is_empty(),
        "{} disagreement(s) with the shared host corpus: {disagreements:#?}",
        disagreements.len()
    );
}
