//! Fuzz the wire decode + reassembly paths: arbitrary datagram bytes must never
//! panic. Run with: `cargo +nightly fuzz run instruction_decode`.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = mish_ssp::instruction::Instruction::decode(data);
    let mut d = mish_ssp::frag::Defragmenter::new();
    if let Some(payload) = d.push(data) {
        let _ = mish_ssp::instruction::Instruction::decode(&payload);
    }
});
