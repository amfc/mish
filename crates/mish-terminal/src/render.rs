//! Render a [`Screen`] to ANSI escape sequences for display on a real terminal.
//!
//! This is what the **client** uses to paint the synchronized screen onto the
//! user's actual TTY. For now it does a full repaint each frame; a future,
//! diff-aware renderer (mosh's `terminaldisplay`) can paint only changed cells.
//!
//! Color mapping note: named colors other than the default fg/bg are not yet
//! fully mapped (we only carry the emulator's discriminant), so named colors
//! render as the terminal default. Indexed and RGB colors render exactly.

use crate::screen::{Cell, Color, Screen, NAMED_BACKGROUND, NAMED_FOREGROUND};
use crate::screen::{F_BOLD, F_DIM, F_HIDDEN, F_INVERSE, F_ITALIC, F_STRIKEOUT, F_UNDERLINE};

/// Render a full-screen repaint: clear, then write every row, then place the
/// cursor and set its visibility.
pub fn render_full(screen: &Screen) -> Vec<u8> {
    let mut out = String::new();
    // Reset attributes, clear screen, home cursor.
    out.push_str("\x1b[0m\x1b[2J\x1b[H");

    for row in 0..screen.rows {
        // Move to start of row (1-based).
        out.push_str(&format!("\x1b[{};1H", row + 1));
        let mut prev_flags = u16::MAX;
        let mut prev_fg = None;
        let mut prev_bg = None;
        for col in 0..screen.cols {
            let cell = screen.cell(row, col).expect("in bounds");
            // Skip the spacer half of a wide character.
            if cell.flags & crate::screen::F_WIDE_SPACER != 0 {
                continue;
            }
            if cell.flags != prev_flags || prev_fg != Some(cell.fg) || prev_bg != Some(cell.bg) {
                out.push_str(&sgr(cell));
                prev_flags = cell.flags;
                prev_fg = Some(cell.fg);
                prev_bg = Some(cell.bg);
            }
            out.push(cell.c);
        }
        out.push_str("\x1b[0m");
    }

    // Cursor visibility + position (1-based).
    out.push_str(if screen.cursor_visible {
        "\x1b[?25h"
    } else {
        "\x1b[?25l"
    });
    out.push_str(&format!(
        "\x1b[{};{}H",
        screen.cursor_row + 1,
        screen.cursor_col + 1
    ));

    out.into_bytes()
}

/// Build the SGR (Select Graphic Rendition) sequence for a cell's attributes.
fn sgr(cell: &Cell) -> String {
    let mut codes: Vec<String> = vec!["0".into()]; // reset first
    let f = cell.flags;
    if f & F_BOLD != 0 {
        codes.push("1".into());
    }
    if f & F_DIM != 0 {
        codes.push("2".into());
    }
    if f & F_ITALIC != 0 {
        codes.push("3".into());
    }
    if f & F_UNDERLINE != 0 {
        codes.push("4".into());
    }
    if f & F_INVERSE != 0 {
        codes.push("7".into());
    }
    if f & F_HIDDEN != 0 {
        codes.push("8".into());
    }
    if f & F_STRIKEOUT != 0 {
        codes.push("9".into());
    }
    push_color(&mut codes, cell.fg, true);
    push_color(&mut codes, cell.bg, false);
    format!("\x1b[{}m", codes.join(";"))
}

fn push_color(codes: &mut Vec<String>, color: Color, fg: bool) {
    match color {
        Color::Named(NAMED_FOREGROUND) | Color::Named(NAMED_BACKGROUND) => {
            // default fg/bg — nothing beyond the leading reset.
        }
        Color::Named(_) => { /* unmapped named color → default */ }
        Color::Indexed(i) => {
            codes.push(if fg { "38".into() } else { "48".into() });
            codes.push("5".into());
            codes.push(i.to_string());
        }
        Color::Rgb(r, g, b) => {
            codes.push(if fg { "38".into() } else { "48".into() });
            codes.push("2".into());
            codes.push(r.to_string());
            codes.push(g.to_string());
            codes.push(b.to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::emulator::Emulator;
    use crate::screen::{Screen, F_WIDE, F_WIDE_SPACER};

    /// The strongest correctness property: the ANSI we emit, replayed through a
    /// real terminal emulator, must reconstruct the screen we rendered. This
    /// proves `render_full` (and `sgr`/`push_color`) emit faithful escape codes.
    ///
    /// We feed attributes and indexed/RGB colors (not named colors or wide chars,
    /// which `render_full` documents as lossy) so the round-trip is exact.
    #[test]
    fn render_full_roundtrips_through_emulator() {
        let mut emu = Emulator::new(20, 4);
        emu.feed(
            b"\x1b[1mBold\x1b[0m \x1b[4mUnder\x1b[0m\r\n\
              \x1b[38;5;200mIdx\x1b[0m \x1b[38;2;10;20;30;48;2;1;2;3mRGB\x1b[0m\r\n\
              \x1b[3;7mit-inv\x1b[0m plain",
        );
        // Move the cursor somewhere non-trivial and hide it.
        emu.feed(b"\x1b[2;5H\x1b[?25l");
        let original = emu.snapshot();

        let ansi = render_full(&original);

        let mut replay = Emulator::new(20, 4);
        replay.feed(&ansi);
        let reconstructed = replay.snapshot();

        assert_eq!(reconstructed.cells, original.cells, "cells must round-trip");
        assert_eq!(
            (reconstructed.cursor_row, reconstructed.cursor_col),
            (original.cursor_row, original.cursor_col),
            "cursor position must round-trip"
        );
        assert_eq!(
            reconstructed.cursor_visible, original.cursor_visible,
            "cursor visibility must round-trip"
        );
    }

    #[test]
    fn sgr_emits_expected_codes() {
        let cell = Cell {
            c: 'x',
            fg: Color::Rgb(10, 20, 30),
            bg: Color::Indexed(200),
            flags: F_BOLD | F_UNDERLINE | F_INVERSE | F_STRIKEOUT,
            ..Default::default()
        };
        let s = sgr(&cell);
        // Leading reset, then each attribute, then truecolor fg and indexed bg.
        assert_eq!(s, "\x1b[0;1;4;7;9;38;2;10;20;30;48;5;200m");
    }

    #[test]
    fn dim_italic_hidden_flags_render() {
        let cell = Cell {
            flags: F_DIM | F_ITALIC | F_HIDDEN,
            ..Default::default()
        };
        assert_eq!(sgr(&cell), "\x1b[0;2;3;8m");
    }

    #[test]
    fn named_colors_fall_back_to_default() {
        let mut codes = vec!["0".to_string()];
        push_color(&mut codes, Color::Named(7), true); // unmapped named → no code
        push_color(&mut codes, Color::Named(NAMED_BACKGROUND), false);
        assert_eq!(codes, vec!["0".to_string()], "named colors add nothing");
    }

    #[test]
    fn hidden_cursor_and_blank_screen_render() {
        let mut screen = Screen::blank(3, 2);
        screen.cursor_visible = false;
        let out = String::from_utf8(render_full(&screen)).unwrap();
        assert!(out.contains("\x1b[2J"), "clears the screen");
        assert!(out.contains("\x1b[?25l"), "hides the cursor");
        assert!(out.ends_with("\x1b[1;1H"), "homes the cursor (1-based)");
    }

    #[test]
    fn wide_spacer_cells_are_skipped() {
        // A wide glyph occupies a cell plus a spacer; render must not emit the
        // spacer (which would push everything one column right).
        let mut screen = Screen::blank(4, 1);
        screen.cells[0] = Cell {
            c: '世',
            flags: F_WIDE,
            ..Default::default()
        };
        screen.cells[1] = Cell {
            c: ' ',
            flags: F_WIDE_SPACER,
            ..Default::default()
        };
        let out = String::from_utf8(render_full(&screen)).unwrap();
        let glyphs: String = out.chars().filter(|c| *c == '世').collect();
        assert_eq!(glyphs, "世", "the wide glyph is emitted exactly once");
    }
}
