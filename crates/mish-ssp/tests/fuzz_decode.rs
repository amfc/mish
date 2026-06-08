//! Robustness ("smoke fuzz") tests: the untrusted decode paths must never panic
//! on arbitrary bytes — these process whatever arrives off the wire. Uses
//! proptest so it runs in normal `cargo test` (no external fuzzing toolchain);
//! a `cargo-fuzz` target can layer on top of the same functions.

use mish_ssp::frag::Defragmenter;
use mish_ssp::instruction::Instruction;
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    /// Decoding an arbitrary datagram never panics (returns None on garbage).
    #[test]
    fn instruction_decode_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let _ = Instruction::decode(&bytes);
    }

    /// Feeding arbitrary datagrams to the reassembler never panics; if it ever
    /// yields a payload, that payload decodes-or-not without panicking.
    #[test]
    fn defragmenter_never_panics(
        datagrams in proptest::collection::vec(
            proptest::collection::vec(any::<u8>(), 0..256), 0..32)
    ) {
        let mut d = Defragmenter::new();
        for dg in &datagrams {
            if let Some(payload) = d.push(dg) {
                let _ = Instruction::decode(&payload);
            }
        }
    }

    /// A round-trip-then-corrupt: encode a valid instruction, flip arbitrary
    /// bytes, and decode — must not panic.
    #[test]
    fn corrupted_instruction_decode(
        flips in proptest::collection::vec((0usize..64, any::<u8>()), 0..16),
    ) {
        let inst = Instruction {
            protocol_version: 1,
            seq: 5,
            old_num: 1, new_num: 2, ack_num: 0, throwaway_num: 0,
            diff: vec![1, 2, 3, 4, 5],
            timestamp: 7, timestamp_reply: Some(3),
        };
        let mut bytes = inst.encode();
        for (i, b) in flips {
            if i < bytes.len() { bytes[i] ^= b; }
        }
        let _ = Instruction::decode(&bytes);
    }
}
