//! Robustness ("smoke fuzz") tests for the untrusted terminal paths: applying an
//! arbitrary diff to a Screen, and feeding arbitrary bytes to the emulator, must
//! never panic (and must not allocate an absurd grid from a hostile header).

use mish_ssp::state::SyncState;
use mish_terminal::emulator::Emulator;
use mish_terminal::screen::Screen;
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// Applying arbitrary bytes as a diff never panics or OOMs.
    #[test]
    fn screen_apply_arbitrary_diff(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let mut s = Screen::blank(80, 24);
        s.apply_diff(&bytes);
        // Whatever happened, the screen stays internally consistent.
        prop_assert_eq!(s.cells.len(), s.cols as usize * s.rows as usize);
    }

    /// A diff header with huge dimensions is rejected, not allocated.
    #[test]
    fn screen_apply_rejects_huge_dims(ansi in proptest::collection::vec(any::<u8>(), 0..64)) {
        let mut header = Vec::new();
        header.extend_from_slice(&0u64.to_le_bytes()); // echo_ack
        header.extend_from_slice(&65535u16.to_le_bytes()); // cols
        header.extend_from_slice(&65535u16.to_le_bytes()); // rows
        header.extend_from_slice(&ansi);
        let mut s = Screen::blank(80, 24);
        s.apply_diff(&header); // must not try to allocate ~4 billion cells
        prop_assert_eq!((s.cols, s.rows), (80, 24)); // unchanged
    }

    /// Feeding arbitrary VT bytes to the emulator never panics.
    #[test]
    fn emulator_feed_arbitrary(chunks in proptest::collection::vec(
        proptest::collection::vec(any::<u8>(), 0..128), 0..16))
    {
        let mut e = Emulator::new(40, 10);
        for c in &chunks {
            e.feed(c);
        }
        let _ = e.snapshot();
    }
}
