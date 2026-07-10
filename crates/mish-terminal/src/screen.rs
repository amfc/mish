//! The `Complete` state: a snapshot of the terminal screen (server → client).
//!
//! This is mosh's `Framebuffer` — what gets synchronized is the *rendered
//! screen*, not the raw byte stream. The server runs the emulator and ships
//! screen snapshots; the client just displays them. This module is deliberately
//! **free of any alacritty dependency** so the protocol state is pure data and
//! can be property-/simulation-tested in isolation. The alacritty → [`Screen`]
//! conversion lives in [`crate::emulator`].
//!
//! The diff is **row-granular**: only changed rows travel on the wire (plus
//! cursor/title), which is what keeps a terminal session cheap to sync.

use mish_ssp::state::SyncState;
use serde::{Deserialize, Serialize};

/// A terminal color. Mirrors the three cases an emulator distinguishes.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Color {
    /// A named/default palette slot (the emulator's `NamedColor` discriminant).
    /// `u16` because the discriminants for default fg/bg are 256/257 — they must
    /// not be truncated into the basic 0–15 range (that bug aliased the default
    /// background onto red).
    Named(u16),
    /// A 256-color palette index.
    Indexed(u8),
    /// A true-color RGB value.
    Rgb(u8, u8, u8),
}

// Default-color discriminants, matching vte's `NamedColor::Foreground`/
// `Background`. Blank cells use these so they compare equal to emulator-produced
// empty cells.
/// Default foreground (`NamedColor::Foreground` discriminant).
pub const NAMED_FOREGROUND: u16 = 256;
/// Default background (`NamedColor::Background` discriminant).
pub const NAMED_BACKGROUND: u16 = 257;

// Cell attribute flags (a curated subset of the emulator's flags).
pub const F_INVERSE: u16 = 1 << 0;
pub const F_BOLD: u16 = 1 << 1;
pub const F_ITALIC: u16 = 1 << 2;
pub const F_UNDERLINE: u16 = 1 << 3;
pub const F_DIM: u16 = 1 << 4;
pub const F_HIDDEN: u16 = 1 << 5;
pub const F_STRIKEOUT: u16 = 1 << 6;
pub const F_WIDE: u16 = 1 << 7;
pub const F_WIDE_SPACER: u16 = 1 << 8;

// Mouse-reporting modes (bitfield on `Screen::mouse_mode`).
pub const MOUSE_CLICK: u8 = 1 << 0; // DECSET 1000
pub const MOUSE_DRAG: u8 = 1 << 1; // DECSET 1002
pub const MOUSE_MOTION: u8 = 1 << 2; // DECSET 1003
pub const MOUSE_SGR: u8 = 1 << 3; // DECSET 1006

// Cursor shapes (`Screen::cursor_shape`).
pub const CURSOR_BLOCK: u8 = 0;
pub const CURSOR_UNDERLINE: u8 = 1;
pub const CURSOR_BEAM: u8 = 2;

/// An OSC 8 hyperlink (`id` is optional; `uri` is the target).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Hyperlink {
    pub id: Option<String>,
    pub uri: String,
}

/// A single screen cell: one base character, its rendering attributes, any
/// zero-width combining marks attached to it (e.g. `e` + U+0301 = `é`), and an
/// optional OSC 8 hyperlink.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Cell {
    pub c: char,
    pub fg: Color,
    pub bg: Color,
    pub flags: u16,
    /// Combining (zero-width) characters following the base glyph.
    pub combining: Vec<char>,
    /// OSC 8 hyperlink covering this cell, if any.
    pub hyperlink: Option<Hyperlink>,
}

impl Default for Cell {
    fn default() -> Self {
        Cell {
            c: ' ',
            fg: Color::Named(NAMED_FOREGROUND),
            bg: Color::Named(NAMED_BACKGROUND),
            flags: 0,
            combining: Vec::new(),
            hyperlink: None,
        }
    }
}

/// A full terminal screen snapshot.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Screen {
    pub cols: u16,
    pub rows: u16,
    /// `rows * cols` cells in row-major order.
    pub cells: Vec<Cell>,
    pub cursor_row: u16,
    pub cursor_col: u16,
    pub cursor_visible: bool,
    pub title: String,
    /// How many of the client's `UserStream` events the server had applied when
    /// this screen was produced (mosh's "echo ack"). The client uses it to
    /// validate or cull speculative local predictions. Server→client only.
    pub echo_ack: u64,
    /// Bracketed-paste mode (DECSET 2004) is active.
    pub bracketed_paste: bool,
    /// Mouse-reporting modes (`MOUSE_*` bitfield).
    pub mouse_mode: u8,
    /// Cursor shape (`CURSOR_*`).
    pub cursor_shape: u8,
    /// Cursor blink.
    pub cursor_blink: bool,
    /// Focus-event reporting (DECSET 1004) is active.
    pub focus_event: bool,
    /// Alternate-scroll mode (DECSET 1007) is active. Defaults *on* (alacritty's
    /// default), so blank/initial screens set it true to match the emulator.
    pub alternate_scroll: bool,
    /// The remote app is on the alternate screen (DECSET 1049 — vim, less,
    /// htop…). Carried so the client can route the mouse wheel correctly: at the
    /// shell prompt (primary screen) the wheel drives mosh scrollback, but on the
    /// alternate screen it must reach the app (which owns its own scrolling).
    /// Not a real-terminal mode — the client never replays it; it's a routing
    /// hint, so it travels out-of-band in the diff header, not the escape stream.
    pub alt_screen: bool,
    /// Latest OSC 52 clipboard contents set by the remote application
    /// (latest-wins; `None` until something sets it). Server→client.
    pub clipboard: Option<String>,
    /// Application-cursor-keys mode (DECCKM, DECSET 1) is active. Replayed onto
    /// the client's terminal so its arrow keys send the SS3 form the remote app
    /// expects (e.g. inside vim/less).
    pub app_cursor_keys: bool,
    /// Monotonic count of terminal bells (BEL). The diff emits the delta as BEL
    /// bytes, so the client rings once per remote beep.
    pub bell_count: u64,
}

impl Screen {
    /// A blank screen of the given size.
    pub fn blank(cols: u16, rows: u16) -> Self {
        Screen {
            cols,
            rows,
            cells: vec![Cell::default(); cols as usize * rows as usize],
            cursor_row: 0,
            cursor_col: 0,
            cursor_visible: true,
            title: String::new(),
            echo_ack: 0,
            bracketed_paste: false,
            mouse_mode: 0,
            cursor_shape: 0,
            cursor_blink: false,
            focus_event: false,
            alternate_scroll: true,
            alt_screen: false,
            clipboard: None,
            app_cursor_keys: false,
            bell_count: 0,
        }
    }

    pub fn cell(&self, row: u16, col: u16) -> Option<&Cell> {
        if row < self.rows && col < self.cols {
            self.cells
                .get(row as usize * self.cols as usize + col as usize)
        } else {
            None
        }
    }

    fn row_slice(&self, row: u16) -> &[Cell] {
        let w = self.cols as usize;
        let start = row as usize * w;
        &self.cells[start..start + w]
    }

    /// The screen as plain text, one `String` per row with trailing blanks
    /// trimmed. Handy for assertions and debugging (attributes are ignored).
    /// Wide-character spacer cells are skipped so wide glyphs aren't doubled.
    pub fn to_lines(&self) -> Vec<String> {
        use unicode_width::UnicodeWidthChar;
        (0..self.rows)
            .map(|r| {
                let row = self.row_slice(r);
                let mut s = String::new();
                let mut x = 0;
                while x < row.len() {
                    let c = row[x].c;
                    s.push(c);
                    // Skip the spacer cell that follows a wide glyph.
                    x += UnicodeWidthChar::width(c).unwrap_or(1).max(1);
                }
                let trimmed = s.trim_end().len();
                s.truncate(trimmed);
                s
            })
            .collect()
    }

    /// The whole screen as text, rows joined by newlines.
    pub fn to_text(&self) -> String {
        self.to_lines().join("\n")
    }

    /// A copy of this screen fitted to a different terminal size by **clipping or
    /// padding from the top-left** — used for read-only viewers of a shared
    /// session whose own terminal differs from the owner's ("owner drives, viewers
    /// clip", `NEXT_FEATURES.md` #3). Overlapping cells are copied verbatim; any
    /// new area is blank; the cursor is clamped into range. Screen-wide state
    /// (title, mouse/cursor/paste modes, clipboard, `echo_ack`, …) is preserved —
    /// only the grid geometry changes. This is a viewport crop, **not** a terminal
    /// reflow: long lines are cut, never rewrapped.
    ///
    /// The target dimensions are **clamped to [`MAX_VIEW_DIM`]** before
    /// allocating. A viewer's geometry is client-controlled (it arrives as a
    /// `UserStream` resize), so an absurd size — e.g. `65535×65535` ≈ 4.3 billion
    /// cells — must not let a read-only viewer OOM the shared server. The cap
    /// mirrors [`MAX_SCREEN_CELLS`]; a real terminal is never near it, so clamping
    /// only ever affects hostile or buggy input.
    pub fn resized_view(&self, cols: u16, rows: u16) -> Screen {
        let cols = cols.min(MAX_VIEW_DIM);
        let rows = rows.min(MAX_VIEW_DIM);
        if self.cols == cols && self.rows == rows {
            return self.clone();
        }
        let mut out = self.clone();
        out.cols = cols;
        out.rows = rows;
        out.cells = vec![Cell::default(); cols as usize * rows as usize];
        let copy_rows = rows.min(self.rows) as usize;
        let copy_cols = cols.min(self.cols) as usize;
        for r in 0..copy_rows {
            let src = r * self.cols as usize;
            let dst = r * cols as usize;
            out.cells[dst..dst + copy_cols].clone_from_slice(&self.cells[src..src + copy_cols]);
        }
        out.cursor_row = self.cursor_row.min(rows.saturating_sub(1));
        out.cursor_col = self.cursor_col.min(cols.saturating_sub(1));
        out
    }
}

/// Diff header (little-endian) preceding the mosh `new_frame` escape stream:
/// `echo_ack: u64 | cols: u16 | rows: u16 | flags: u8`. Dimensions tell the
/// receiver whether the escape stream is an incremental frame (same dims) or a
/// full repaint (resized), echo_ack is the out-of-band prediction-validation
/// counter, and `flags` carries state that isn't reproducible from the escape
/// stream (bit 0: `alt_screen`).
const DIFF_HEADER: usize = 13;

/// `flags` bit: the remote app is on the alternate screen.
const FLAG_ALT_SCREEN: u8 = 1 << 0;

/// Upper bound on a synchronized screen's cell count, to reject malformed or
/// hostile diffs that would allocate an absurd grid (a generous ~2000×2000).
const MAX_SCREEN_CELLS: u32 = 4_000_000;

/// Per-dimension clamp for [`Screen::resized_view`], whose target geometry is
/// client-controlled (a viewer's `UserStream` resize). Capping each side keeps
/// the cell count within [`MAX_SCREEN_CELLS`] so a read-only viewer can't OOM the
/// server by reporting an enormous terminal. No real terminal approaches this.
const MAX_VIEW_DIM: u16 = 2000;
// The clamp is only sound if a fully-clamped grid stays within the cell budget.
const _: () = assert!((MAX_VIEW_DIM as u64) * (MAX_VIEW_DIM as u64) <= MAX_SCREEN_CELLS as u64);

impl SyncState for Screen {
    fn new_initial() -> Self {
        // Both peers agree on a 0×0 empty screen at num 0; the first real diff
        // resizes and fills it.
        Screen {
            cols: 0,
            rows: 0,
            cells: Vec::new(),
            cursor_row: 0,
            cursor_col: 0,
            cursor_visible: true,
            title: String::new(),
            echo_ack: 0,
            bracketed_paste: false,
            mouse_mode: 0,
            cursor_shape: 0,
            cursor_blink: false,
            focus_event: false,
            alternate_scroll: true,
            alt_screen: false,
            clipboard: None,
            app_cursor_keys: false,
            bell_count: 0,
        }
    }

    fn diff_from(&self, prev: &Self) -> Vec<u8> {
        // The diff is mosh's minimal escape stream transforming `prev` into
        // `self` (cursor moves, ECH/EL erases, SGR runs) — see `crate::display`.
        let ansi = crate::display::new_frame(prev, self, true, "");
        if ansi.is_empty() && self.echo_ack == prev.echo_ack && self.alt_screen == prev.alt_screen {
            return Vec::new();
        }
        let flags = if self.alt_screen { FLAG_ALT_SCREEN } else { 0 };
        let mut out = Vec::with_capacity(DIFF_HEADER + ansi.len());
        out.extend_from_slice(&self.echo_ack.to_le_bytes());
        out.extend_from_slice(&self.cols.to_le_bytes());
        out.extend_from_slice(&self.rows.to_le_bytes());
        out.push(flags);
        out.extend_from_slice(&ansi);
        out
    }

    fn apply_diff(&mut self, diff: &[u8]) {
        if diff.len() < DIFF_HEADER {
            return; // empty (no-op) or malformed
        }
        let echo_ack = u64::from_le_bytes(diff[0..8].try_into().unwrap());
        let cols = u16::from_le_bytes([diff[8], diff[9]]);
        let rows = u16::from_le_bytes([diff[10], diff[11]]);
        let flags = diff[12];
        let ansi = &diff[DIFF_HEADER..];

        // Reject degenerate or implausibly large geometries from a malformed/
        // hostile diff. A zero dimension slips past the product check (0 × huge ==
        // 0) yet makes the emulator's grid panic building a zero-width/height row;
        // an enormous product would allocate an absurd grid. A *single-column*
        // grid panics too: a wide (CJK) glyph writes its spacer to column 1, which
        // is out of bounds in alacritty's 1-wide row (`cursor_cell` index OOB,
        // found by the `screen_apply` fuzzer). A 1-column terminal can't render
        // wide chars anyway and never occurs in practice, so require cols >= 2.
        if cols < 2 || rows == 0 || cols as u32 * rows as u32 > MAX_SCREEN_CELLS {
            return;
        }

        // Reconstruct the new screen by replaying the escape stream through a
        // throwaway emulator. When dimensions are unchanged the stream is an
        // incremental frame from `self` (== the reference state we were cloned
        // from), so we first paint `self`; when resized, the stream is a full
        // repaint and paints from blank.
        let mut emu = crate::emulator::Emulator::new(cols, rows);
        if cols == self.cols && rows == self.rows {
            let blank = Screen::blank(cols, rows);
            emu.feed(&crate::display::new_frame(&blank, self, false, ""));
        }
        emu.feed(ansi);
        let mut next = emu.snapshot();
        next.echo_ack = echo_ack;
        // `alt_screen` can't be reconstructed from the escape stream (the client
        // never replays 1049), so restore it from the header flags.
        next.alt_screen = flags & FLAG_ALT_SCREEN != 0;
        *self = next;
    }

    fn equals(&self, other: &Self) -> bool {
        self == other
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Only the (miri-excluded) proptest block below uses this.
    #[cfg(not(miri))]
    use proptest::prelude::*;

    /// Regression (found by the `screen_apply` cargo-fuzz target): a diff header
    /// declaring a zero dimension slips past the cell-count guard (0 × huge == 0)
    /// but makes the emulator's grid panic building a zero-width row. apply_diff
    /// must reject degenerate and oversized geometries without panicking.
    #[test]
    fn malformed_diff_geometry_does_not_panic() {
        let make = |cols: u16, rows: u16| {
            let mut d = Vec::new();
            d.extend_from_slice(&0u64.to_le_bytes()); // echo_ack
            d.extend_from_slice(&cols.to_le_bytes());
            d.extend_from_slice(&rows.to_le_bytes());
            d.push(b'\n'); // some escape-stream payload
            d
        };
        // Includes cols == 1 (the `screen_apply` fuzzer's 1-column case): a real
        // wide glyph in a 1-wide row makes alacritty's grid panic, so it's rejected
        // like the zero/oversized geometries.
        for (cols, rows) in [
            (0, 0xe6e6),
            (0xe6e6, 0),
            (0, 0),
            (1, 24),
            (1, 256),
            (u16::MAX, u16::MAX),
        ] {
            let mut s = Screen::blank(80, 24);
            s.apply_diff(&make(cols, rows)); // must not panic
                                             // Degenerate/oversized geometry is rejected → screen left unchanged.
            assert_eq!((s.cols, s.rows), (80, 24));
        }

        // The exact shrunk fuzzer counterexample: cols=1, rows=256, then a wide
        // CJK glyph (U+2E80, UTF-8 e2 ba 80) whose spacer would land out of bounds.
        let mut d = 0u64.to_le_bytes().to_vec();
        d.extend_from_slice(&1u16.to_le_bytes()); // cols = 1
        d.extend_from_slice(&256u16.to_le_bytes()); // rows
        d.push(0); // flags
        d.extend_from_slice(&[0xe2, 0xba, 0x80]); // wide glyph payload
        let mut s = Screen::blank(80, 24);
        s.apply_diff(&d); // must not panic
        assert_eq!((s.cols, s.rows), (80, 24));
    }

    /// `resized_view` crops/pads from the top-left, preserves screen-wide state,
    /// clamps the cursor, and is identity at the same size — the contract the
    /// shared-session viewer path relies on ("owner drives, viewers clip").
    #[test]
    fn resized_view_clips_pads_and_clamps() {
        // Fill a 4×3 screen with distinct glyphs so cropping is observable.
        let mut s = Screen::blank(4, 3);
        for r in 0..3u16 {
            for c in 0..4u16 {
                s.cells[r as usize * 4 + c as usize].c = char::from(b'a' + (r * 4 + c) as u8);
            }
        }
        s.cursor_row = 2;
        s.cursor_col = 3;
        s.title = "hi".into();
        s.echo_ack = 7;

        // Identity at the same size.
        assert_eq!(s.resized_view(4, 3), s);

        // Crop to 2×2: keep the top-left block; cursor clamps to (1,1).
        let small = s.resized_view(2, 2);
        assert_eq!((small.cols, small.rows), (2, 2));
        assert_eq!(small.to_lines(), vec!["ab".to_string(), "ef".to_string()]);
        assert_eq!((small.cursor_row, small.cursor_col), (1, 1));
        assert_eq!(small.title, "hi"); // screen-wide state preserved
        assert_eq!(small.echo_ack, 7);

        // Pad to 6×4: original content stays top-left, new area is blank, and the
        // cursor (in range) is unchanged.
        let big = s.resized_view(6, 4);
        assert_eq!((big.cols, big.rows), (6, 4));
        assert_eq!(big.cells.len(), 24);
        assert_eq!(big.to_lines()[0], "abcd"); // trailing blanks trimmed
        assert_eq!(big.to_lines()[3], ""); // padded row is blank
        assert_eq!((big.cursor_row, big.cursor_col), (2, 3));
    }

    /// Security: a viewer's reported geometry is client-controlled, so an absurd
    /// size must be clamped rather than allocated — a read-only viewer must not be
    /// able to OOM the shared server (the analogue of `apply_diff`'s
    /// `MAX_SCREEN_CELLS` guard). The worst case (`65535×65535` ≈ 4.3 billion
    /// cells) must not panic and must stay within the cell budget.
    ///
    /// Skipped under Miri: it allocates the full clamped grid (~4M cells), far too
    /// much for Miri's interpreter. The clamp is a size-bound property, not a
    /// memory-safety one — `resized_view`'s UB-freedom is proved by the Kani
    /// harness, and the small resize tests above cover it under Miri.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn resized_view_bounds_hostile_dimensions() {
        let s = Screen::blank(80, 24);
        let big = s.resized_view(u16::MAX, u16::MAX);
        assert!(
            big.cells.len() as u32 <= MAX_SCREEN_CELLS,
            "resized_view allocated {} cells, over the {MAX_SCREEN_CELLS} budget",
            big.cells.len()
        );
        assert!(big.cols <= MAX_VIEW_DIM && big.rows <= MAX_VIEW_DIM);
        assert_eq!(big.cells.len(), big.cols as usize * big.rows as usize);
    }

    // Excluded under Miri: each case allocates up to a clamped 2000×2000 grid and
    // proptest runs dozens of them — orders of magnitude too slow for Miri. Kani
    // proves `resized_view` panic-free over the bounded domain instead.
    #[cfg(not(miri))]
    proptest! {
        // Each case can allocate up to a clamped 2000×2000 grid, so keep the case
        // count modest — the hostile-dimension space is small and well-covered.
        #![proptest_config(ProptestConfig::with_cases(48))]
        /// For *any* client-reported target geometry (full u16 range) and a small
        /// source screen, `resized_view` never panics, the result is internally
        /// consistent (cells == cols*rows), the cursor stays in range, and the
        /// allocation stays within the cell budget.
        #[test]
        fn resized_view_is_panic_free_and_bounded(
            src_cols in 0u16..120,
            src_rows in 0u16..50,
            cols in any::<u16>(),
            rows in any::<u16>(),
        ) {
            let src = Screen::blank(src_cols, src_rows);
            let out = src.resized_view(cols, rows);
            prop_assert_eq!(out.cells.len(), out.cols as usize * out.rows as usize);
            prop_assert!(out.cells.len() as u32 <= MAX_SCREEN_CELLS);
            prop_assert!(out.cols <= MAX_VIEW_DIM && out.rows <= MAX_VIEW_DIM);
            if out.cols > 0 {
                prop_assert!(out.cursor_col < out.cols);
            }
            if out.rows > 0 {
                prop_assert!(out.cursor_row < out.rows);
            }
        }
    }

    #[test]
    fn short_diff_is_noop() {
        let mut s = Screen::blank(80, 24);
        s.apply_diff(&[]); // empty
        s.apply_diff(&[1, 2, 3]); // shorter than the header
        assert_eq!((s.cols, s.rows), (80, 24));
    }
}
