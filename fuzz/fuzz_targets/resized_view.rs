//! Fuzz `Screen::resized_view`, the shared-session viewer crop/pad
//! (NEXT_FEATURES.md multi-client attach). A read-only viewer's target geometry
//! is **client-controlled** (a `UserStream` resize), so an arbitrary `cols×rows`
//! must never panic and must stay within the cell budget — a viewer must not be
//! able to OOM the server by reporting an absurd terminal size.
//! Run with: `cargo +nightly fuzz run resized_view`.
#![no_main]
use libfuzzer_sys::fuzz_target;

// Mirror of `screen::MAX_SCREEN_CELLS` (private): the memory ceiling the crop
// must respect regardless of the requested dimensions.
const MAX_SCREEN_CELLS: usize = 4_000_000;

fuzz_target!(|data: &[u8]| {
    // First 8 bytes pick a (bounded) source size and an (arbitrary, full-range)
    // target size; the rest fills the source grid so the copy path is exercised.
    let g = |i: usize| -> u16 {
        u16::from_le_bytes([
            data.get(i).copied().unwrap_or(0),
            data.get(i + 1).copied().unwrap_or(0),
        ])
    };
    // Source is bounded so building the *input* stays cheap; the interesting,
    // hostile dimension is the target (cols/rows below), left full-range.
    let src_cols = g(0) % 200;
    let src_rows = g(2) % 100;
    let cols = g(4);
    let rows = g(6);

    let mut src = mish_terminal::screen::Screen::blank(src_cols, src_rows);
    // Scribble arbitrary glyphs into the source so cropped content varies.
    for (cell, &b) in src.cells.iter_mut().zip(data.iter().skip(8)) {
        cell.c = char::from(b);
    }

    let out = src.resized_view(cols, rows);

    // The whole point: the crop is internally consistent and memory-bounded even
    // for a maximally hostile requested size.
    assert_eq!(out.cells.len(), out.cols as usize * out.rows as usize);
    assert!(out.cells.len() <= MAX_SCREEN_CELLS);
});
