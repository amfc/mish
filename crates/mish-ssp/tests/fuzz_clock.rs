//! Clock-fuzzing: the sans-IO core takes `now` as an argument, so a buggy or
//! adjusted system clock (NTP steps, suspend/resume, a non-monotonic source)
//! feeds it surprising timestamps. The core's timer/RTT math does subtractions
//! on these values — a naive `now - last` underflows on a backwards step.
//!
//! Two properties:
//!  - SAFETY (arbitrary, including backwards, time): never panic, keep the
//!    receive queue bounded.
//!  - LIVENESS (monotonic time with large forward jumps — the realistic NTP/
//!    suspend case): the exchange still converges.

use mish_ssp::core::SspCore;
use mish_ssp::states::BytesState;
use proptest::prelude::*;

type Core = SspCore<BytesState, BytesState>;

/// Timestamps spanning the interesting edges plus fully-arbitrary values, so the
/// sequence freely jumps forwards, backwards, and to the u64 boundaries.
fn arb_time() -> impl Strategy<Value = u64> {
    prop_oneof![
        Just(0u64),
        Just(1),
        Just(u64::MAX),
        Just(u64::MAX - 1),
        0u64..1000,
        any::<u64>(),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1500))]

    /// Arbitrary (non-monotonic, jumping, boundary) clock values must never panic
    /// the core and must keep its memory bounded.
    #[test]
    fn chaotic_clock_is_safe(
        times in proptest::collection::vec(arb_time(), 0..300),
        payload in proptest::collection::vec(any::<u8>(), 1..32),
    ) {
        let mut a = Core::new(0);
        let mut b = Core::new(0);
        a.set_current_state(BytesState::new(payload));

        for &t in &times {
            // tick/recv/next_wakeup/wait_time all consume `now`; exercise them
            // all at each (possibly backwards) timestamp.
            for inst in a.tick(t) {
                b.recv(t, &inst);
            }
            for inst in b.tick(t) {
                a.recv(t, &inst);
            }
            let _ = a.next_wakeup(t);
            let _ = b.wait_time(t);
            prop_assert!(a.received_state_count() <= 1025);
            prop_assert!(b.received_state_count() <= 1025);
        }
    }

    /// Monotonic time with occasional huge forward jumps (NTP step / wake from
    /// suspend) must not break liveness — the receiver still converges.
    #[test]
    fn forward_jumps_still_converge(
        deltas in proptest::collection::vec(prop_oneof![0u64..50, 1_000_000u64..u32::MAX as u64], 0..40),
        payload in proptest::collection::vec(any::<u8>(), 1..32),
    ) {
        let mut a = Core::new(0);
        let mut b = Core::new(0);
        a.set_current_state(BytesState::new(payload.clone()));

        let mut now = 0u64;
        // Drive through the (jumpy but monotonic) schedule...
        for &d in &deltas {
            now = now.saturating_add(d);
            for inst in a.tick(now) { b.recv(now, &inst); }
            for inst in b.tick(now) { a.recv(now, &inst); }
        }
        // ...then let it settle on a steady cadence and require convergence.
        for _ in 0..5000 {
            now = now.saturating_add(20);
            for inst in a.tick(now) { b.recv(now, &inst); }
            for inst in b.tick(now) { a.recv(now, &inst); }
            if b.remote_state().as_slice() == payload.as_slice() {
                break;
            }
        }
        prop_assert_eq!(
            b.remote_state().as_slice(),
            payload.as_slice(),
            "must converge despite forward clock jumps"
        );
    }
}
