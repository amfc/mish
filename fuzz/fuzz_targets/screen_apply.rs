//! Fuzz the screen-diff apply path (header parse + emulator replay): an
//! arbitrary diff must never panic or allocate an absurd grid.
//! Run with: `cargo +nightly fuzz run screen_apply`.
#![no_main]
use libfuzzer_sys::fuzz_target;
use mish_ssp::state::SyncState;

fuzz_target!(|data: &[u8]| {
    let mut s = mish_terminal::screen::Screen::blank(80, 24);
    s.apply_diff(data);
});
