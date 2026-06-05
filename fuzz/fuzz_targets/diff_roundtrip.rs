//! Coverage-guided diff round-trip: drive a *real* emulator with arbitrary VT
//! bytes to produce two successive screens, then assert the wire diff
//! reconstructs the second from the first:
//!
//!   prev.clone().apply_diff(cur.diff_from(&prev)) == cur
//!
//! Because the screens come from the emulator (never hand-built), they are
//! always well-formed — so unlike the structured `fuzz_diff` test this target is
//! free to exercise wide characters and combining marks, the cases that test
//! deliberately excludes. libFuzzer's coverage feedback steers the byte stream
//! into the emulator/diff branches proptest's bounded random sampling misses.
//!
//! Run with: `cargo +nightly fuzz run diff_roundtrip`.
#![no_main]
use libfuzzer_sys::fuzz_target;
use mish_ssp::state::SyncState;
use mish_terminal::emulator::Emulator;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    // First byte picks the split point between the two byte chunks.
    let split = (data[0] as usize) % data.len();
    let (first, second) = data[1..].split_at(split.min(data.len() - 1));

    let mut emu = Emulator::new(40, 12);
    emu.feed(first);
    let prev = emu.snapshot();
    emu.feed(second);
    let cur = emu.snapshot();

    let diff = cur.diff_from(&prev);
    let mut rebuilt = prev.clone();
    rebuilt.apply_diff(&diff);
    assert_eq!(rebuilt, cur, "diff failed to reconstruct the screen");
});
