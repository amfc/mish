//! Kani bounded-proof harnesses for the **structural core of the screen path**.
//!
//! These are the proof companion to the `screen_apply` / `resized_view` libFuzzer
//! targets. Where the fuzzers *sample* diffs and geometries looking for a crash,
//! Kani symbolically explores **every** geometry within an explicit bound and
//! proves the absence of panics, out-of-bounds indexing, and malformed output —
//! a complete result over that bounded domain rather than a probabilistic one.
//!
//! ## Why `resized_view` / `cell` and not `apply_diff`
//!
//! `apply_diff` parses a fixed header and then *replays an escape stream through
//! the alacritty-backed [`crate::emulator::Emulator`]* — whose VT parser and grid
//! are opaque, loop-heavy, and intractable for a solver. That surface stays the
//! `screen_apply` / `client_render_safety` fuzzers' job. What *is* tractable, and
//! is the part carrying the real index/arithmetic risk, is the pure geometry code
//! the client reconstruction leans on: the bounds-checked `cell` accessor and the
//! `resized_view` crop/pad — no emulator, just `Vec<Cell>` slicing and `u16`
//! arithmetic, exactly the shape Kani discharges cleanly.
//!
//! The structural properties proved here — the output grid is `cols*rows` cells,
//! target geometry is honored, the cursor lands in range, and every crop/pad
//! slice stays in bounds — are *independent of the cell contents and of the
//! magnitudes* of the dimensions. So we hold the cells at their concrete default
//! and use a small dimension bound that still spans the crop (target < source),
//! pad (target > source), equal, and zero-dimension regimes: a sound, tractable
//! proof of a structural property.
//!
//! Run with: `cargo kani -p mish-terminal` (harnesses are `#[cfg(kani)]`, so they
//! never enter a normal `cargo build` / `cargo test`).

use crate::screen::Screen;

/// Largest grid dimension the solver picks for either the source screen or the
/// resize target. Kept small on purpose — the properties are structural, so a
/// bound that exercises every branch (crop, pad, equal, zero) is enough.
///
/// The separate clamp to `MAX_VIEW_DIM` (2000) inside `resized_view` is *not*
/// exercised here: it's a one-line `.min()` already guarded by a compile-time
/// `const assert!` (cols·rows ≤ `MAX_SCREEN_CELLS`) plus the
/// `resized_view_bounds_hostile_dimensions` unit test, and tripping it would
/// force a multi-million-cell allocation far past any tractable unwind. Within
/// this bound the clamp is identity, so `out.cols == cols` holds exactly.
const MAX_DIM: u16 = 3;

/// A symbolic dimension in `0..=MAX_DIM`.
fn symbolic_dim() -> u16 {
    let d: u16 = kani::any();
    kani::assume(d <= MAX_DIM);
    d
}

/// A well-formed source screen with symbolic geometry and an in-range cursor.
///
/// Cells stay at their concrete default — the structural invariants don't depend
/// on cell contents, so holding them concrete keeps the proof tractable while
/// every geometry within the bound is still explored. The cursor precondition
/// (`< dim`, or 0 on an empty axis) is what a *well-formed* screen always
/// satisfies; `resized_view`'s equal-dimension fast path returns the screen
/// unchanged, so it only preserves the cursor-in-range invariant if the input
/// had it — making the precondition load-bearing, not cosmetic.
fn symbolic_screen() -> Screen {
    let cols = symbolic_dim();
    let rows = symbolic_dim();
    // `blank` allocates exactly `cols * rows` default cells, so the screen starts
    // structurally well-formed (`cells.len() == cols * rows`).
    let mut s = Screen::blank(cols, rows);

    let cr: u16 = kani::any();
    let cc: u16 = kani::any();
    kani::assume(cr < rows || rows == 0);
    kani::assume(cc < cols || cols == 0);
    s.cursor_row = cr;
    s.cursor_col = cc;
    s
}

/// `resized_view` never panics and always returns a structurally well-formed
/// screen, for *every* source geometry, target geometry, and cursor position
/// within the bound.
///
/// Proves:
///   * no panic / out-of-bounds slice in the crop+pad copy loop (the
///     `out.cells[dst..dst + copy_cols]` and `self.cells[src..src + copy_cols]`
///     accesses are always in range);
///   * `out.cells.len() == out.cols * out.rows` — the grid stays rectangular;
///   * `out.cols == cols && out.rows == rows` — the requested geometry is honored
///     (the `MAX_VIEW_DIM` clamp is identity within the bound);
///   * the cursor is clamped into the new grid (`< dim`, or 0 on a 0-length axis).
#[kani::proof]
#[kani::unwind(12)]
#[kani::solver(kissat)]
fn resized_view_is_well_formed() {
    let src = symbolic_screen();
    let cols = symbolic_dim();
    let rows = symbolic_dim();

    let out = src.resized_view(cols, rows);

    assert_eq!(
        out.cells.len(),
        out.cols as usize * out.rows as usize,
        "resized grid must be exactly cols*rows cells"
    );
    assert_eq!(out.cols, cols, "target columns must be honored");
    assert_eq!(out.rows, rows, "target rows must be honored");
    assert!(
        out.rows == 0 || out.cursor_row < out.rows,
        "cursor row must be clamped into the new grid"
    );
    assert!(
        out.cols == 0 || out.cursor_col < out.cols,
        "cursor column must be clamped into the new grid"
    );
}

/// `Screen::cell` is a sound bounds-checked accessor: it returns `Some` exactly
/// for in-grid coordinates and never indexes out of bounds, for every screen
/// geometry and coordinate within the bound.
///
/// The `is_some() == in_grid` equivalence proves both directions at once: the
/// `row < rows && col < cols` guard is *necessary* (out-of-grid ⇒ `None`) and
/// *sufficient* (in-grid ⇒ the computed `row*cols + col` index is `< cells.len()`,
/// so `.get` yields `Some`) — i.e. a well-formed screen's row-major index never
/// escapes its backing buffer.
#[kani::proof]
#[kani::unwind(12)]
#[kani::solver(kissat)]
fn cell_access_is_bounds_checked() {
    let s = symbolic_screen();
    let row: u16 = kani::any();
    let col: u16 = kani::any();

    let in_grid = row < s.rows && col < s.cols;
    assert_eq!(s.cell(row, col).is_some(), in_grid);
}
