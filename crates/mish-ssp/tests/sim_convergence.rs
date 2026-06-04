//! Deterministic, virtual-time convergence tests for the SSP core, driven by
//! [`mish_ssp::sim::NetworkSim`]. These exercise the protocol end-to-end (both
//! directions) under perfect, lossy, and reordering links without any async or
//! real time — and are perfectly reproducible from the seed.

use mish_ssp::sim::{NetworkSim, SimConfig};
use mish_ssp::states::BytesState;

const MAX_TIME: u64 = 300_000;

fn converged(sim: &NetworkSim<BytesState, BytesState>, a: &[u8], b: &[u8]) -> bool {
    sim.b_view_of_a().as_slice() == a && sim.a_view_of_b().as_slice() == b
}

#[test]
fn lossless_one_way() {
    let mut sim = NetworkSim::<BytesState, BytesState>::new(SimConfig::default());
    sim.set_a_local(BytesState::new(b"hello world".to_vec()));
    let ok = sim.run_until(|s| s.b_view_of_a().as_slice() == b"hello world", MAX_TIME);
    assert!(ok, "B should receive A's state (t={})", sim.now());
    assert_eq!(sim.dropped, 0);
}

#[test]
fn lossless_two_way() {
    let mut sim = NetworkSim::<BytesState, BytesState>::new(SimConfig::default());
    sim.set_a_local(BytesState::new(b"from A".to_vec()));
    sim.set_b_local(BytesState::new(b"from B".to_vec()));
    let ok = sim.run_until(|s| converged(s, b"from A", b"from B"), MAX_TIME);
    assert!(ok, "both directions should converge (t={})", sim.now());
}

#[test]
fn sequential_updates_converge_to_latest() {
    // The protocol is latest-wins: intermediate states may be skipped, but the
    // final state must always be delivered.
    let mut sim = NetworkSim::<BytesState, BytesState>::new(SimConfig::default());
    for step in 0..20u8 {
        sim.set_a_local(BytesState::new(format!("state-{step}").into_bytes()));
        // Run a little between updates so some intermediate states actually ship.
        let target = sim.now() + 5;
        sim.run_until(|s| s.now() >= target, MAX_TIME);
    }
    let ok = sim.run_until(|s| s.b_view_of_a().as_slice() == b"state-19", MAX_TIME);
    assert!(
        ok,
        "B converges to the final state (saw {:?})",
        String::from_utf8_lossy(sim.b_view_of_a().as_slice())
    );
}

#[test]
fn converges_under_heavy_loss() {
    let cfg = SimConfig {
        loss: 0.5,
        min_delay: 5,
        max_delay: 40, // jitter ⇒ reordering
        seed: 0xCAFEF00D,
        ..Default::default()
    };
    let mut sim = NetworkSim::<BytesState, BytesState>::new(cfg);
    sim.set_a_local(BytesState::new(b"survives 50% loss".to_vec()));
    sim.set_b_local(BytesState::new(b"and reordering".to_vec()));
    let ok = sim.run_until(
        |s| converged(s, b"survives 50% loss", b"and reordering"),
        MAX_TIME,
    );
    assert!(
        ok,
        "should converge despite loss (t={}, sent={}, dropped={})",
        sim.now(),
        sim.sent,
        sim.dropped
    );
    assert!(sim.dropped > 0, "test should actually exercise loss");
}

#[test]
fn converges_across_many_seeds() {
    // Same scenario, different impairment sequences — guards against seed-luck.
    for seed in 0..32u64 {
        let cfg = SimConfig {
            loss: 0.4,
            min_delay: 1,
            max_delay: 50,
            seed: seed.wrapping_mul(0x9E3779B97F4A7C15) | 1,
            ..Default::default()
        };
        let mut sim = NetworkSim::<BytesState, BytesState>::new(cfg);
        sim.set_a_local(BytesState::new(format!("payload-{seed}").into_bytes()));
        let want = format!("payload-{seed}").into_bytes();
        let ok = sim.run_until(|s| s.b_view_of_a().as_slice() == want.as_slice(), MAX_TIME);
        assert!(ok, "seed {seed} failed to converge (t={})", sim.now());
    }
}
