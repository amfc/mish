//! Property-based tests (proptest).
//!
//! Two layers:
//!   1. State-level invariants the protocol depends on ([`SyncState`] contract).
//!   2. End-to-end: for *any* sequence of state changes and *any* impairment
//!      profile, the receiver eventually converges to the sender's final state.

use mish_ssp::sim::{NetworkSim, SimConfig};
use mish_ssp::state::SyncState;
use mish_ssp::states::BytesState;
use proptest::prelude::*;

// ---- Layer 1: SyncState contract ----

proptest! {
    /// Round-trip: applying `b.diff_from(a)` to a clone of `a` reconstructs `b`.
    #[test]
    fn diff_apply_roundtrip(a in any::<Vec<u8>>(), b in any::<Vec<u8>>()) {
        let prev = BytesState::new(a);
        let target = BytesState::new(b);
        let diff = target.diff_from(&prev);
        let mut applied = prev.clone();
        applied.apply_diff(&diff);
        prop_assert!(applied.equals(&target));
    }

    /// Idempotency: applying the same diff twice equals applying it once.
    #[test]
    fn diff_apply_idempotent(a in any::<Vec<u8>>(), b in any::<Vec<u8>>()) {
        let prev = BytesState::new(a);
        let target = BytesState::new(b);
        let diff = target.diff_from(&prev);
        let mut once = prev.clone();
        once.apply_diff(&diff);
        let mut twice = once.clone();
        twice.apply_diff(&diff);
        prop_assert!(once.equals(&twice));
    }

    /// Equal states diff to an empty change.
    #[test]
    fn equal_states_empty_diff(a in any::<Vec<u8>>()) {
        let s = BytesState::new(a);
        prop_assert!(s.diff_from(&s).is_empty());
    }
}

// ---- Layer 2: end-to-end convergence ----

proptest! {
    // Fewer cases: each runs a full simulation.
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// For any payload, any loss in [0, 0.6), any delay jitter, and any seed, B
    /// converges to A's final state within the time budget.
    #[test]
    fn converges_for_any_link(
        payload in proptest::collection::vec(any::<u8>(), 0..256),
        loss in 0.0f64..0.6,
        max_delay in 1u64..80,
        seed in any::<u64>(),
    ) {
        let cfg = SimConfig {
            loss,
            min_delay: 1,
            max_delay,
            seed: seed | 1,
            ..Default::default()
        };
        let mut sim = NetworkSim::<BytesState, BytesState>::new(cfg);
        sim.set_a_local(BytesState::new(payload.clone()));
        let want = payload.clone();
        let ok = sim.run_until(
            move |s| s.b_view_of_a().as_slice() == want.as_slice(),
            600_000,
        );
        prop_assert!(ok, "did not converge: t={} sent={} dropped={}", sim.now(), sim.sent, sim.dropped);
    }

    /// Latest-wins: after a sequence of updates, B converges to the *last* one,
    /// regardless of loss.
    #[test]
    fn converges_to_latest_of_sequence(
        updates in proptest::collection::vec(
            proptest::collection::vec(any::<u8>(), 0..32), 1..12),
        loss in 0.0f64..0.5,
        seed in any::<u64>(),
    ) {
        let cfg = SimConfig { loss, min_delay: 1, max_delay: 30, seed: seed | 1, ..Default::default() };
        let mut sim = NetworkSim::<BytesState, BytesState>::new(cfg);
        for u in &updates {
            sim.set_a_local(BytesState::new(u.clone()));
            let t = sim.now() + 3;
            sim.run_until(|s| s.now() >= t, 600_000);
        }
        let want = updates.last().unwrap().clone();
        let ok = sim.run_until(move |s| s.b_view_of_a().as_slice() == want.as_slice(), 600_000);
        prop_assert!(ok, "did not converge to latest: t={}", sim.now());
    }
}
