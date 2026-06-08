//! Hostile-peer robustness: a peer (or an attacker who got past the crypto
//! layer) feeding arbitrary, replayed, reordered, or truncated traffic must
//! never panic, hang, or grow memory without bound — and must not break an
//! honest exchange happening alongside the noise.
//!
//! (Wire authenticity is QUIC/TLS's job; this hardens the layer *below* that
//! against malformed/adversarial input.)

use mish_ssp::core::SspCore;
use mish_ssp::frag::Defragmenter;
use mish_ssp::instruction::{Instruction, PROTOCOL_VERSION, SHUTDOWN_NUM};
use mish_ssp::states::BytesState;
use proptest::prelude::*;

type Core = SspCore<BytesState, BytesState>;

/// Instructions spanning the interesting edge values (0, 1, MAX, SHUTDOWN).
fn arb_num() -> impl Strategy<Value = u64> {
    prop_oneof![
        Just(0u64),
        Just(1),
        Just(SHUTDOWN_NUM),
        Just(u64::MAX - 1),
        any::<u64>(),
        0u64..8,
    ]
}

fn arb_instruction() -> impl Strategy<Value = Instruction> {
    (
        prop_oneof![Just(PROTOCOL_VERSION), any::<u32>()],
        any::<u64>(),
        arb_num(),
        arb_num(),
        arb_num(),
        arb_num(),
        proptest::collection::vec(any::<u8>(), 0..64),
        any::<u16>(),
        proptest::option::of(any::<u16>()),
    )
        .prop_map(
            |(
                protocol_version,
                seq,
                old_num,
                new_num,
                ack_num,
                throwaway_num,
                diff,
                timestamp,
                timestamp_reply,
            )| {
                Instruction {
                    protocol_version,
                    seq,
                    old_num,
                    new_num,
                    ack_num,
                    throwaway_num,
                    diff,
                    timestamp,
                    timestamp_reply,
                }
            },
        )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1500))]

    /// Feeding arbitrary instructions never panics and keeps the receive queue
    /// bounded; the core remains functional afterward.
    #[test]
    fn hostile_instructions_bounded_and_safe(insts in proptest::collection::vec(arb_instruction(), 0..400)) {
        let mut core = Core::new(0);
        let mut now = 0u64;
        for inst in &insts {
            core.recv(now, inst);
            now += 1;
            // The receive queue must never exceed the configured cap (+ a small
            // slack for the in-progress insert).
            prop_assert!(core.received_state_count() <= 1025, "receive queue unbounded: {}", core.received_state_count());
        }
        // Still functional: ticking doesn't panic and produces well-formed output.
        let _ = core.tick(now + 1);
    }

    /// The instruction codec (now deflate-compressed behind a flag byte) round-
    /// trips any instruction: encode then decode reproduces it exactly. Arbitrary
    /// bytes fed to `decode` already exercise the inflate path in the safety tests
    /// below; this pins the happy path including the compressed branch.
    #[test]
    fn codec_roundtrips(inst in arb_instruction()) {
        let encoded = inst.encode();
        let decoded = Instruction::decode(&encoded);
        prop_assert_eq!(decoded.as_ref(), Some(&inst));
    }

    /// Arbitrary datagram bytes through the full reassemble->decode->recv pipeline
    /// never panic.
    #[test]
    fn hostile_datagram_bytes_safe(datagrams in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..300), 0..40)) {
        let mut core = Core::new(0);
        let mut defrag = Defragmenter::new();
        for (i, dg) in datagrams.iter().enumerate() {
            if let Some(payload) = defrag.push(dg) {
                if let Some(inst) = Instruction::decode(&payload) {
                    core.recv(i as u64, &inst);
                }
            }
        }
        prop_assert!(core.received_state_count() <= 1025);
    }

    /// An honest sender converges with an honest receiver even while a stream of
    /// random *bytes* is injected into the receiver (undecodable noise is dropped;
    /// it must not derail the real exchange).
    #[test]
    fn honest_exchange_survives_byte_noise(noise in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..200), 0..60)) {
        let mut a = Core::new(0); // sender
        let mut b = Core::new(0); // receiver
        let mut bdefrag = Defragmenter::new();
        a.set_current_state(BytesState::new(b"hello world".to_vec()));
        let mut noise = noise.into_iter();
        let mut now = 0u64;
        for _ in 0..3000 {
            now += 20;
            for inst in a.tick(now) { b.recv(now, &inst); }
            // Inject undecodable noise into b's receive pipeline.
            if let Some(garbage) = noise.next() {
                if let Some(payload) = bdefrag.push(&garbage) {
                    if let Some(inst) = Instruction::decode(&payload) {
                        b.recv(now, &inst);
                    }
                }
            }
            for inst in b.tick(now) { a.recv(now, &inst); }
            if b.remote_state().as_slice() == b"hello world" {
                break;
            }
        }
        prop_assert_eq!(b.remote_state().as_slice(), b"hello world", "honest exchange must converge despite noise");
    }
}
