//! Security target — the **answerback loopback**. Terminal query sequences a
//! program prints (DA/DSR/CPR/DECRQSS, OSC color/size queries, title reports)
//! make the emulator emit a reply that the server writes *back into the program's
//! PTY input* (`Emulator::take_answerback`). That is an output→stdin channel: if a
//! crafted program could make the reply contain a line terminator, it would inject
//! a command into the shell's input (the classic xterm title-report injection).
//!
//! Invariant: whatever bytes a program can drive into the answerback, the reply
//! must never contain CR or LF (no line submission / command injection) and must
//! stay bounded (no amplification). A failure here is a real injection bug, not a
//! crash.
//!
//! Run with: `cargo +nightly fuzz run answerback_safety`.
#![no_main]
use libfuzzer_sys::fuzz_target;
use mish_terminal::emulator::Emulator;

fuzz_target!(|data: &[u8]| {
    let mut emu = Emulator::new(80, 24);

    // Split the input so the fuzzer can *set* state (e.g. a title) in one feed and
    // *query* it in another — the reflection path that historically leaked
    // attacker-controlled bytes into the answerback.
    let split = if data.is_empty() {
        0
    } else {
        (data[0] as usize) % data.len()
    };
    let (a, b) = data.split_at(split);

    let mut reply = Vec::new();
    emu.feed(a);
    reply.extend_from_slice(&emu.take_answerback());
    emu.feed(b);
    reply.extend_from_slice(&emu.take_answerback());

    // No carriage return / line feed — these are what would submit or split a
    // command line if injected into the shell's stdin.
    assert!(
        !reply.contains(&b'\n') && !reply.contains(&b'\r'),
        "answerback leaked a line terminator (command-injection): {:?}",
        reply
    );
    // Bounded: the reply must not amplify the program's output without limit.
    assert!(
        reply.len() <= data.len().saturating_mul(64) + 4096,
        "answerback amplified {} input bytes to {} reply bytes",
        data.len(),
        reply.len()
    );
});
