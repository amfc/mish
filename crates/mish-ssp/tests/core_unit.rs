//! Focused unit tests for [`mish_ssp::core::SspCore`] receiver semantics,
//! driving instructions by hand to pin down idempotency and replay-safety —
//! the security-sensitive parts of SSP.

use mish_ssp::core::SspCore;
use mish_ssp::instruction::{Instruction, PROTOCOL_VERSION};
use mish_ssp::states::BytesState;

type Core = SspCore<BytesState, BytesState>;

#[test]
fn initial_tick_emits_keepalive_ack() {
    let mut a = Core::new(0);
    let out = a.tick(0);
    assert_eq!(out.len(), 1, "should emit an initial empty ack");
    assert!(out[0].diff.is_empty());
    assert_eq!(out[0].new_num, 1);
    assert_eq!(out[0].old_num, 0);
}

#[test]
fn diff_is_delivered_and_idempotent() {
    let mut a = Core::new(0);
    let mut b = Core::new(0);

    a.set_current_state(BytesState::new(b"hello".to_vec()));
    let out = a.tick(0);
    let inst = out
        .into_iter()
        .find(|i| i.has_diff())
        .expect("a data instruction");

    b.recv(0, &inst);
    assert_eq!(b.remote_state().as_slice(), b"hello");
    let num = b.remote_state_num();

    // Replaying the exact same instruction must not change anything.
    b.recv(0, &inst);
    assert_eq!(b.remote_state().as_slice(), b"hello");
    assert_eq!(b.remote_state_num(), num, "duplicate must be ignored");
}

#[test]
fn unknown_old_num_is_dropped() {
    let mut b = Core::new(0);
    let bogus = Instruction {
        protocol_version: PROTOCOL_VERSION,
        seq: 0,
        old_num: 999, // b has no such reference state
        new_num: 1000,
        ack_num: 0,
        throwaway_num: 0,
        diff: BytesState::new(b"evil".to_vec()).as_slice().to_vec(),
        timestamp: 0,
        timestamp_reply: None,
    };
    b.recv(0, &bogus);
    assert_eq!(
        b.remote_state().as_slice(),
        b"",
        "must not apply unanchored diff"
    );
    assert_eq!(b.remote_state_num(), 0);
}

#[test]
fn wrong_protocol_version_ignored() {
    let mut b = Core::new(0);
    let inst = Instruction {
        protocol_version: PROTOCOL_VERSION + 1,
        seq: 0,
        old_num: 0,
        new_num: 1,
        ack_num: 0,
        throwaway_num: 0,
        diff: vec![],
        timestamp: 0,
        timestamp_reply: None,
    };
    b.recv(0, &inst);
    assert_eq!(b.remote_state_num(), 0);
}

#[test]
fn ack_advances_sender_to_synced() {
    let mut a = Core::new(0);
    let mut b = Core::new(0);

    // A sends "data" to B.
    a.set_current_state(BytesState::new(b"data".to_vec()));
    for inst in a.tick(0) {
        b.recv(0, &inst);
    }
    assert!(!a.is_synced(), "A is not synced until B acks");
    assert_eq!(b.remote_state().as_slice(), b"data");

    // B's reply carries an ack for A's state; once A hears it, A is synced.
    // Advance time so B emits its delayed ack.
    let mut now: u64 = 0;
    for _ in 0..100 {
        now += 20;
        for inst in b.tick(now) {
            a.recv(now, &inst);
        }
        for inst in a.tick(now) {
            b.recv(now, &inst);
        }
        if a.is_synced() {
            break;
        }
    }
    assert!(
        a.is_synced(),
        "A should become synced after B acks (t={now})"
    );
}

#[test]
fn shutdown_handshake_both_sides_close() {
    let mut a = Core::new(0);
    let mut b = Core::new(0);

    a.start_shutdown();
    let mut now: u64 = 0;
    for _ in 0..100 {
        now += 20;
        for inst in a.tick(now) {
            b.recv(now, &inst);
        }
        // The peer mirrors the shutdown once it sees ours.
        if b.peer_is_shutting_down() {
            b.start_shutdown();
        }
        for inst in b.tick(now) {
            a.recv(now, &inst);
        }
        if a.is_shutdown_acked() && b.is_shutdown_acked() {
            break;
        }
    }
    assert!(a.is_shutdown_acked(), "A's shutdown acknowledged by B");
    assert!(b.is_shutdown_acked(), "B's shutdown acknowledged by A");
    assert!(a.peer_is_shutting_down());
    assert!(b.peer_is_shutting_down());
}

/// The three-leg shutdown handshake completes even when shutdown datagrams are
/// lost: the core resends SHUTDOWN_NUM at the frame rate until acked, so both
/// sides still reach a clean close (mosh's SHUTDOWN_RETRIES robustness). Run
/// across several drop patterns for confidence.
#[test]
fn shutdown_converges_under_loss() {
    for seed in [1u64, 7, 42, 1234, 99999] {
        let mut a = Core::new(0);
        let mut b = Core::new(0);
        a.start_shutdown();

        // Deterministic ~40%-loss xorshift, distinct per seed.
        let mut rng = seed.wrapping_mul(2654435761).wrapping_add(1);
        let mut drop = move || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng % 5 < 2 // ~40%
        };

        let mut now = 0u64;
        let mut closed = false;
        for _ in 0..2000 {
            now += 20;
            for inst in a.tick(now) {
                if !drop() {
                    b.recv(now, &inst);
                }
            }
            if b.peer_is_shutting_down() {
                b.start_shutdown();
            }
            for inst in b.tick(now) {
                if !drop() {
                    a.recv(now, &inst);
                }
            }
            if a.is_shutdown_acked() && b.is_shutdown_acked() {
                closed = true;
                break;
            }
        }
        assert!(
            closed,
            "shutdown handshake should converge under loss (seed {seed})"
        );
    }
}

#[test]
fn malformed_diff_does_not_panic() {
    // A diff that isn't a valid BytesState diff: recv must not panic in release;
    // in debug the BytesState debug_assert is bypassed because we go through the
    // protocol's empty-diff fast path only for empty diffs. Use a >=4 byte diff
    // with a huge prefix len, which truncate handles gracefully.
    let mut b = Core::new(0);
    let inst = Instruction {
        protocol_version: PROTOCOL_VERSION,
        seq: 0,
        old_num: 0,
        new_num: 1,
        ack_num: 0,
        throwaway_num: 0,
        diff: vec![0xff, 0xff, 0xff, 0xff, b'x'], // prefix len ~4B, tail "x"
        timestamp: 0,
        timestamp_reply: None,
    };
    b.recv(0, &inst);
    // truncate(huge) is a no-op on an empty vec, then "x" is appended.
    assert_eq!(b.remote_state().as_slice(), b"x");
}

/// Tick `c` (advancing virtual time) until it emits, returning the instructions.
fn tick_until_emit(c: &mut Core, now: &mut u64) -> Vec<Instruction> {
    for _ in 0..2000 {
        let out = c.tick(*now);
        if !out.is_empty() {
            return out;
        }
        *now += 5;
    }
    panic!("core never emitted");
}

/// The prophylactic-resend optimization (mosh's
/// `attempt_prospective_resend_optimization`): when a sent-but-only-*assumed*-
/// delivered state is actually lost, the next send anchors its diff on the
/// *acked* front state instead, so the peer recovers a round-trip sooner.
#[test]
fn prospective_resend_recovers_from_a_lost_datagram() {
    let mut a = Core::new(0);
    let mut b = Core::new(0);
    let mut now = 0u64;

    // 1. a → "v1"; deliver it; b acks; a learns v1 is acked (front advances to v1).
    a.set_current_state(BytesState::new(b"v1".to_vec()));
    for i in tick_until_emit(&mut a, &mut now) {
        b.recv(now, &i);
    }
    now += 5;
    for i in tick_until_emit(&mut b, &mut now) {
        a.recv(now, &i);
    }

    // 2. a → "v1v2"; it is sent but the datagram is LOST (never reaches b). a now
    //    *assumes* b has v1v2, but b is still at v1.
    a.set_current_state(BytesState::new(b"v1v2".to_vec()));
    let lost = tick_until_emit(&mut a, &mut now);
    assert_eq!(lost[0].new_num, 2, "v1v2 was sent (and dropped)");

    // 3. a → "v1v2v3"; the next send should anchor on the acked front (v1, num 1),
    //    not the merely-assumed (and lost) v1v2 (num 2).
    a.set_current_state(BytesState::new(b"v1v2v3".to_vec()));
    let resent = tick_until_emit(&mut a, &mut now);
    assert_eq!(
        resent[0].old_num, 1,
        "diff anchored on the acked front, not the lost assumed state"
    );

    // 4. Because the diff builds on v1 (which b has), b recovers straight to
    //    v1v2v3 despite never receiving v1v2 — one round-trip sooner than if the
    //    diff had been anchored on the lost state (which b would have dropped).
    b.recv(now, &resent[0]);
    assert_eq!(
        b.remote_state().as_slice(),
        b"v1v2v3",
        "peer recovers from the lost datagram in a single step"
    );
}

// ---------------------------------------------------------------------------
// Timer-recompute elision (pending_wait after tick == wait_time)
// ---------------------------------------------------------------------------

/// The driver reads `pending_wait` instead of recomputing timers via `wait_time`.
/// They must agree right after a `tick`, across the protocol's distinct states:
/// fresh, with pending data, just-sent (unacked retransmit pending), and idle.
#[test]
fn pending_wait_matches_wait_time_after_tick() {
    let mut a = Core::new(0);
    let mut now: u64 = 0;
    let check = |a: &mut Core, now: u64, ctx: &str| {
        a.tick(now); // leaves timers fresh
        let pending = a.pending_wait(now);
        let recomputed = a.wait_time(now); // recomputes calculate_timers
        assert_eq!(
            pending, recomputed,
            "pending_wait diverged from wait_time: {ctx}"
        );
    };

    check(&mut a, now, "initial");

    // Pending local data not yet due to send.
    a.set_current_state(BytesState::new(b"hello".to_vec()));
    check(&mut a, now, "data pending");

    // Advance past the send time so the next tick actually sends; afterwards the
    // retransmit timer must be the one both agree on.
    now += 50;
    check(&mut a, now, "after a data send");

    // Idle for a while: still must agree.
    now += 5000;
    check(&mut a, now, "idle");
}
