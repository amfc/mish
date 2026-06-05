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
fn converges_under_duplication() {
    // Duplicate datagrams must be harmless (the protocol is idempotent on state
    // application): convergence still holds, and a duplicate is actually exercised.
    let cfg = SimConfig {
        dup: 0.5,
        min_delay: 1,
        max_delay: 30,
        seed: 0x0D15EA5E,
        ..Default::default()
    };
    let mut sim = NetworkSim::<BytesState, BytesState>::new(cfg);
    sim.set_a_local(BytesState::new(b"duplicated state".to_vec()));
    sim.set_b_local(BytesState::new(b"also duplicated".to_vec()));
    let ok = sim.run_until(
        |s| converged(s, b"duplicated state", b"also duplicated"),
        MAX_TIME,
    );
    assert!(ok, "should converge despite duplication (t={})", sim.now());
    assert!(
        sim.duplicated > 0,
        "test should actually exercise duplication"
    );
}

#[test]
fn converges_under_corruption() {
    // Corruption on an authenticated wire = the datagram fails auth and is dropped
    // (see `NetworkSim::enqueue`), so it behaves as an extra loss source and
    // convergence must still hold.
    let cfg = SimConfig {
        corrupt: 0.4,
        min_delay: 1,
        max_delay: 30,
        seed: 0xBADC0FFEE,
        ..Default::default()
    };
    let mut sim = NetworkSim::<BytesState, BytesState>::new(cfg);
    // Drive a stream of updates so plenty of datagrams flow (and get corrupted).
    for step in 0..10u32 {
        sim.set_a_local(BytesState::new(format!("flip-{step}").into_bytes()));
        let target = sim.now() + 10;
        sim.run_until(|s| s.now() >= target, MAX_TIME);
    }
    sim.set_a_local(BytesState::new(b"survives bit flips".to_vec()));
    sim.set_b_local(BytesState::new(b"and so do I".to_vec()));
    let ok = sim.run_until(
        |s| converged(s, b"survives bit flips", b"and so do I"),
        MAX_TIME,
    );
    assert!(ok, "should converge despite corruption (t={})", sim.now());
    assert!(
        sim.corrupted > 0,
        "test should actually exercise corruption"
    );
}

#[test]
fn soak_combined_faults_many_seeds() {
    // Long soak: loss + duplication + corruption + reordering, all at once, across
    // many seeds and with a stream of state updates. Asserts (a) eventual
    // convergence to the latest state and (b) bounded receive-queue memory at every
    // step throughout the run — the protocol must never accumulate unboundedly even
    // under sustained adversarial conditions.
    for seed in 0..40u64 {
        let cfg = SimConfig {
            loss: 0.3,
            dup: 0.2,
            corrupt: 0.15,
            min_delay: 1,
            max_delay: 60,
            seed: seed.wrapping_mul(0x9E3779B97F4A7C15) | 1,
            ..Default::default()
        };
        let mut sim = NetworkSim::<BytesState, BytesState>::new(cfg);

        // Push a stream of updates, advancing time between them so intermediate
        // states actually ship into the lossy/dup/corrupt link.
        for step in 0..15u32 {
            sim.set_a_local(BytesState::new(
                format!("seed-{seed}-step-{step}").into_bytes(),
            ));
            sim.set_b_local(BytesState::new(format!("b-{seed}-{step}").into_bytes()));
            let target = sim.now() + 7;
            sim.run_until(
                |s| {
                    let (ra, rb) = s.received_counts();
                    assert!(
                        ra <= 1025 && rb <= 1025,
                        "receive queue grew unbounded: a={ra} b={rb}"
                    );
                    s.now() >= target
                },
                MAX_TIME,
            );
        }

        let want_a = format!("seed-{seed}-step-14").into_bytes();
        let want_b = format!("b-{seed}-14").into_bytes();
        let ok = sim.run_until(|s| converged(s, &want_a, &want_b), MAX_TIME);
        assert!(
            ok,
            "seed {seed} failed to converge under combined faults \
             (t={}, sent={}, dropped={}, dup={}, corrupt={})",
            sim.now(),
            sim.sent,
            sim.dropped,
            sim.duplicated,
            sim.corrupted
        );
        let (ra, rb) = sim.received_counts();
        assert!(
            ra <= 1025 && rb <= 1025,
            "final receive queue unbounded: a={ra} b={rb}"
        );
    }
}

#[test]
fn converges_under_asymmetric_loss() {
    // A good downlink (A→B) with a terrible uplink (B→A) — the common mobile
    // case. Both directions must still converge.
    let cfg = SimConfig {
        loss: 0.05,
        loss_return: Some(0.6),
        min_delay: 1,
        max_delay: 40,
        seed: 0xA551_0888,
        ..Default::default()
    };
    let mut sim = NetworkSim::<BytesState, BytesState>::new(cfg);
    sim.set_a_local(BytesState::new(b"down is fine".to_vec()));
    sim.set_b_local(BytesState::new(b"up is awful".to_vec()));
    let ok = sim.run_until(|s| converged(s, b"down is fine", b"up is awful"), MAX_TIME);
    assert!(
        ok,
        "asymmetric link must converge both ways (t={}, dropped={}/{})",
        sim.now(),
        sim.dropped,
        sim.sent
    );
}

#[test]
fn converges_with_divergent_peer_clocks() {
    // The two peers' clocks differ by a large constant offset. The protocol's
    // timestamp/RTT math uses wrapping 16-bit timestamps and per-peer relative
    // deltas, so a constant skew must not break convergence.
    for skew in [37_000i64, -50_000, 1_000_000, -1_000_000] {
        let cfg = SimConfig {
            loss: 0.2,
            min_delay: 5,
            max_delay: 30,
            clock_skew_b: skew,
            seed: 0xC10C_C0DE ^ (skew as u64),
            ..Default::default()
        };
        let mut sim = NetworkSim::<BytesState, BytesState>::new(cfg);
        sim.set_a_local(BytesState::new(b"clock A".to_vec()));
        sim.set_b_local(BytesState::new(b"clock B".to_vec()));
        let ok = sim.run_until(|s| converged(s, b"clock A", b"clock B"), MAX_TIME);
        assert!(ok, "skew {skew}ms must still converge (t={})", sim.now());
    }
}

#[test]
fn long_soak_memory_stays_bounded() {
    // A long churn: hundreds of state updates over a lossy/duplicating link, with
    // the receive *and* sent queues asserted bounded at every step — the protocol
    // must not accumulate memory under sustained traffic.
    let cfg = SimConfig {
        loss: 0.25,
        dup: 0.15,
        min_delay: 1,
        max_delay: 30,
        seed: 0x50A4,
        ..Default::default()
    };
    let mut sim = NetworkSim::<BytesState, BytesState>::new(cfg);
    for step in 0..400u32 {
        sim.set_a_local(BytesState::new(format!("a-update-{step}").into_bytes()));
        sim.set_b_local(BytesState::new(format!("b-update-{step}").into_bytes()));
        let target = sim.now() + 5;
        sim.run_until(
            |s| {
                let (ra, rb) = s.received_counts();
                assert!(
                    ra <= 1025 && rb <= 1025,
                    "receive queue grew: a={ra} b={rb}"
                );
                s.now() >= target
            },
            MAX_TIME,
        );
    }
    let want_a = b"a-update-399";
    let want_b = b"b-update-399";
    assert!(
        sim.run_until(|s| converged(s, want_a, want_b), MAX_TIME),
        "must converge after a long churn (t={})",
        sim.now()
    );
    let (ra, rb) = sim.received_counts();
    assert!(
        ra <= 1025 && rb <= 1025,
        "final receive queue: a={ra} b={rb}"
    );
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
