//! Diagnostic counterexamples for LashSesh/thronion at
//! 6369565780b47cb620c5adcde6384ba996250b0e. These assert the observed defects,
//! not the behavior a fixed implementation should provide. Copy into the
//! isolated package's tests/review_probes.rs; no network/service is started.

use std::time::Instant;
use thronion::core::QuantumState;
use thronion::delta::DeltaKernel;
use thronion::resonance::ResonantAbsorber;
use thronion::thronion::{ClassicalSignature, ConversionUtils, ThronionKernel};
use thronion::tor::{CellTypeDistribution, TimingFeatures, TorCircuitMetadata};

fn fixture(bytes: u64) -> (TorCircuitMetadata, TimingFeatures, CellTypeDistribution) {
    (
        TorCircuitMetadata {
            circuit_id: 1,
            created_at: Instant::now(),
            cell_timings: vec![],
            cell_types: vec![],
            introduction_point: None,
            rendezvous_completed: false,
            total_bytes: bytes,
        },
        TimingFeatures {
            mean_interval: 100.0,
            std_dev_interval: 20.0,
            median_interval: 100.0,
            min_interval: 80.0,
            max_interval: 120.0,
        },
        CellTypeDistribution {
            data_ratio: 0.8,
            intro_ratio: 0.1,
            rendezvous_ratio: 0.1,
            padding_ratio: 0.0,
            other_ratio: 0.0,
        },
    )
}

#[test]
fn first_attack_label_does_not_create_an_attack_region() {
    let (metadata, timing, distribution) = fixture(4096);
    let mut kernel = ThronionKernel::new();
    kernel.learn(&metadata, &timing, &distribution, true);
    let (attack, score, region) = kernel.classify(&metadata, &timing, &distribution);
    assert_eq!(kernel.stats().total_regions, 1);
    assert_eq!(kernel.stats().attack_regions, 0);
    assert!(!attack);
    assert!(score > 0.99 && region == Some(0));
}

#[test]
fn region_created_as_benign_cannot_learn_repeated_identical_attack_labels() {
    let (metadata, timing, distribution) = fixture(4096);
    let mut kernel = ThronionKernel::new();
    kernel.learn(&metadata, &timing, &distribution, false);
    for _ in 0..20 {
        kernel.learn(&metadata, &timing, &distribution, true);
    }
    let (attack, score, _) = kernel.classify(&metadata, &timing, &distribution);
    assert!(!attack && score > 0.99);
    assert_eq!(kernel.stats().attack_regions, 0);
}

#[test]
fn zero_bytes_produce_non_finite_features_and_fall_through_to_benign() {
    let (metadata, timing, distribution) = fixture(0);
    let signature = ClassicalSignature::from_metadata(&metadata, &timing, &distribution);
    assert!(signature.to_vector().iter().any(|value| !value.is_finite()));
    let state = ConversionUtils::classical_to_quantum(&signature);
    assert!(state
        .amplitudes
        .iter()
        .any(|value| !value.re.is_finite() || !value.im.is_finite()));
    let (normal, normal_timing, normal_dist) = fixture(4096);
    let mut kernel = ThronionKernel::new();
    kernel.learn(&normal, &normal_timing, &normal_dist, true);
    kernel.learn(&normal, &normal_timing, &normal_dist, true);
    assert!(kernel.classify(&normal, &normal_timing, &normal_dist).0);
    let (attack, score, _) = kernel.classify(&metadata, &timing, &distribution);
    assert!(!attack);
    assert_eq!(score, 0.0);
}

#[test]
fn configured_attack_threshold_does_not_change_classification() {
    let (metadata, timing, distribution) = fixture(4096);
    let mut decisions = Vec::new();
    for threshold in [0.0, 1.0] {
        let mut kernel = ThronionKernel::with_params(threshold, 10, 0.1);
        kernel.learn(&metadata, &timing, &distribution, true);
        kernel.learn(&metadata, &timing, &distribution, true);
        decisions.push(kernel.classify(&metadata, &timing, &distribution));
    }
    assert_eq!(decisions[0], decisions[1]);
    assert!(decisions[0].0);
}

#[test]
fn coherence_is_constant_for_different_normalized_states() {
    let mut kernel = DeltaKernel::default();
    kernel.quantum_state = QuantumState::basis_state(0);
    let basis = kernel.coherence();
    kernel.quantum_state = QuantumState::uniform_superposition();
    let uniform = kernel.coherence();
    assert!((basis - 1.0 / 13.0).abs() < 1e-12);
    assert!((uniform - basis).abs() < 1e-12);
}

#[test]
fn absorption_feedback_can_turn_repeated_blocked_input_into_allowed_input() {
    let mut absorber = ResonantAbsorber::default();
    let packet = [42_u8; 1000];
    let before = absorber.resonance_score(&packet, 0);
    assert!(absorber.process_packet(&packet, 0, 0.379).0);
    let after = absorber.resonance_score(&packet, 0);
    assert!(after > before);
    assert!(!absorber.process_packet(&packet, 0, 0.379).0);
}
