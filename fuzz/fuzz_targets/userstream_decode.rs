//! Fuzz the `UserStream` diff-apply path: an arbitrary (malformed/hostile) diff
//! applied to a UserStream must never panic. UserStream carries keystrokes/
//! resizes (the non-idempotent, security-relevant client→server direction), so
//! its decode path is worth hardening directly.
//!
//! Run with: `cargo +nightly fuzz run userstream_decode`.
#![no_main]
use libfuzzer_sys::fuzz_target;
use mish_ssp::state::SyncState;
use mish_terminal::user::UserStream;

fuzz_target!(|data: &[u8]| {
    // Apply arbitrary bytes as a diff to a fresh stream.
    let mut s = UserStream::new();
    s.apply_diff(data);

    // And to a non-empty stream (exercises the common-prefix / truncation logic).
    let mut s2 = UserStream::new();
    s2.push_keystroke(b"hello".to_vec());
    s2.push_resize(80, 24);
    s2.apply_diff(data);
});
