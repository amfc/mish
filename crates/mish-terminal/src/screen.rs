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
    Named(u8),
    /// A 256-color palette index.
    Indexed(u8),
    /// A true-color RGB value.
    Rgb(u8, u8, u8),
}

// Named-color discriminants we care about for defaults. These match
// alacritty/vte's `NamedColor` enum ordering (Foreground = 256, Background =
// 257 in the palette sense, but as enum discriminants they are small); the
// emulator layer maps real values, so here we only need stable sentinels for
// blank cells.
/// Default foreground sentinel for blank cells.
pub const NAMED_FOREGROUND: u8 = 0;
/// Default background sentinel for blank cells.
pub const NAMED_BACKGROUND: u8 = 1;

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

/// A single screen cell: one character plus its rendering attributes.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Cell {
    pub c: char,
    pub fg: Color,
    pub bg: Color,
    pub flags: u16,
}

impl Default for Cell {
    fn default() -> Self {
        Cell {
            c: ' ',
            fg: Color::Named(NAMED_FOREGROUND),
            bg: Color::Named(NAMED_BACKGROUND),
            flags: 0,
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

/// Wire form of a screen diff (bincode-encoded). Only changed rows are carried.
#[derive(Serialize, Deserialize)]
struct ScreenDiff {
    cols: u16,
    rows: u16,
    /// Set when the dimensions changed (then *every* row is included).
    resized: bool,
    /// `(row_index, row_cells)` for each changed row.
    changed_rows: Vec<(u16, Vec<Cell>)>,
    cursor_row: u16,
    cursor_col: u16,
    cursor_visible: bool,
    /// `Some` only when the title changed.
    title: Option<String>,
}

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
        }
    }

    fn diff_from(&self, prev: &Self) -> Vec<u8> {
        let resized = self.cols != prev.cols || self.rows != prev.rows;

        let mut changed_rows = Vec::new();
        for row in 0..self.rows {
            let differs = resized || self.row_slice(row) != prev.row_slice(row);
            if differs {
                changed_rows.push((row, self.row_slice(row).to_vec()));
            }
        }

        let cursor_changed = self.cursor_row != prev.cursor_row
            || self.cursor_col != prev.cursor_col
            || self.cursor_visible != prev.cursor_visible;
        let title = if self.title != prev.title {
            Some(self.title.clone())
        } else {
            None
        };

        // Nothing changed ⇒ empty diff (SSP treats it as a no-op).
        if !resized && changed_rows.is_empty() && !cursor_changed && title.is_none() {
            return Vec::new();
        }

        let diff = ScreenDiff {
            cols: self.cols,
            rows: self.rows,
            resized,
            changed_rows,
            cursor_row: self.cursor_row,
            cursor_col: self.cursor_col,
            cursor_visible: self.cursor_visible,
            title,
        };
        bincode::serialize(&diff).expect("screen diff serialization is infallible")
    }

    fn apply_diff(&mut self, diff: &[u8]) {
        if diff.is_empty() {
            return;
        }
        let diff: ScreenDiff = match bincode::deserialize(diff) {
            Ok(d) => d,
            Err(_) => return, // malformed; drop
        };

        if diff.resized || diff.cols != self.cols || diff.rows != self.rows {
            self.cols = diff.cols;
            self.rows = diff.rows;
            self.cells = vec![Cell::default(); diff.cols as usize * diff.rows as usize];
        }

        let w = self.cols as usize;
        for (row, cells) in diff.changed_rows {
            if (row as usize) < self.rows as usize && cells.len() == w {
                let start = row as usize * w;
                self.cells[start..start + w].clone_from_slice(&cells);
            }
        }

        self.cursor_row = diff.cursor_row;
        self.cursor_col = diff.cursor_col;
        self.cursor_visible = diff.cursor_visible;
        if let Some(title) = diff.title {
            self.title = title;
        }
    }

    fn equals(&self, other: &Self) -> bool {
        self == other
    }
}
