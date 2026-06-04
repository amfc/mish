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
