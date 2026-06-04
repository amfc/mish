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
    let mut now = 0;
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
    let mut now = 0;
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

#[test]
fn malformed_diff_does_not_panic() {
    // A diff that isn't a valid BytesState diff: recv must not panic in release;
    // in debug the BytesState debug_assert is bypassed because we go through the
    // protocol's empty-diff fast path only for empty diffs. Use a >=4 byte diff
    // with a huge prefix len, which truncate handles gracefully.
    let mut b = Core::new(0);
    let inst = Instruction {
        protocol_version: PROTOCOL_VERSION,
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
