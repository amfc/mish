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
        }
    }

    pub fn cell(&self, row: u16, col: u16) -> Option<&Cell> {
        if row < self.rows && col < self.cols {
            self.cells.get(row as usize * self.cols as usize + col as usize)
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
        (0..self.rows)
            .map(|r| {
                let mut s: String = self
                    .row_slice(r)
                    .iter()
                    .filter(|c| c.flags & F_WIDE_SPACER == 0)
                    .map(|c| c.c)
                    .collect();
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
}

/// Diff header (little-endian) preceding the mosh `new_frame` escape stream:
/// `echo_ack: u64 | cols: u16 | rows: u16`. Dimensions tell the receiver whether
/// the escape stream is an incremental frame (same dims) or a full repaint
/// (resized), and echo_ack is the out-of-band prediction-validation counter.
const DIFF_HEADER: usize = 12;

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
        }
    }

    fn diff_from(&self, prev: &Self) -> Vec<u8> {
        // The diff is mosh's minimal escape stream transforming `prev` into
        // `self` (cursor moves, ECH/EL erases, SGR runs) — see `crate::display`.
        let ansi = crate::display::new_frame(prev, self, true);
        if ansi.is_empty() && self.echo_ack == prev.echo_ack {
            return Vec::new();
        }
        let mut out = Vec::with_capacity(DIFF_HEADER + ansi.len());
        out.extend_from_slice(&self.echo_ack.to_le_bytes());
        out.extend_from_slice(&self.cols.to_le_bytes());
        out.extend_from_slice(&self.rows.to_le_bytes());
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
        let ansi = &diff[DIFF_HEADER..];

        // Reconstruct the new screen by replaying the escape stream through a
        // throwaway emulator. When dimensions are unchanged the stream is an
        // incremental frame from `self` (== the reference state we were cloned
        // from), so we first paint `self`; when resized, the stream is a full
        // repaint and paints from blank.
        let mut emu = crate::emulator::Emulator::new(cols, rows);
        if cols == self.cols && rows == self.rows {
            let blank = Screen::blank(cols, rows);
            emu.feed(&crate::display::new_frame(&blank, self, false));
        }
        emu.feed(ansi);
        let mut next = emu.snapshot();
        next.echo_ack = echo_ack;
        *self = next;
    }

    fn equals(&self, other: &Self) -> bool {
        self == other
    }
}
