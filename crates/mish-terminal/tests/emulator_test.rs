//! Tests that the alacritty-backed [`Emulator`] correctly turns VT byte streams
//! into [`Screen`] snapshots.

use mish_terminal::emulator::Emulator;
use mish_terminal::screen::{self, Color};

#[test]
fn plain_text_lands_on_screen() {
    let mut emu = Emulator::new(20, 5);
    emu.feed(b"hello world");
    let screen = emu.snapshot();
    assert_eq!(screen.cols, 20);
    assert_eq!(screen.rows, 5);
    assert_eq!(screen.to_lines()[0], "hello world");
    // Cursor advanced past the text.
    assert_eq!(screen.cursor_row, 0);
    assert_eq!(screen.cursor_col, 11);
}

#[test]
fn newline_and_carriage_return() {
    let mut emu = Emulator::new(20, 5);
    emu.feed(b"line1\r\nline2");
    let lines = emu.snapshot().to_lines();
    assert_eq!(lines[0], "line1");
    assert_eq!(lines[1], "line2");
}

#[test]
fn cursor_positioning_escape() {
    let mut emu = Emulator::new(20, 5);
    // CUP: move to row 3, col 5 (1-based), then write.
    emu.feed(b"\x1b[3;5HX");
    let screen = emu.snapshot();
    assert_eq!(screen.cursor_row, 2); // 0-based
    assert_eq!(screen.cell(2, 4).unwrap().c, 'X');
}

#[test]
fn sgr_attributes_and_color() {
    let mut emu = Emulator::new(20, 2);
    // Bold + red foreground (indexed 1 via 256-color), then a char.
    emu.feed(b"\x1b[1m\x1b[38;5;196mR");
    let cell = emu.snapshot().cell(0, 0).unwrap().clone();
    assert_eq!(cell.c, 'R');
    assert_ne!(cell.flags & screen::F_BOLD, 0, "bold flag set");
    assert_eq!(cell.fg, Color::Indexed(196));
}

#[test]
fn rgb_truecolor() {
    let mut emu = Emulator::new(10, 1);
    emu.feed(b"\x1b[38;2;10;20;30mZ");
    let cell = emu.snapshot().cell(0, 0).unwrap().clone();
    assert_eq!(cell.fg, Color::Rgb(10, 20, 30));
}

#[test]
fn title_via_osc() {
    let mut emu = Emulator::new(20, 2);
    emu.feed(b"\x1b]0;my-title\x07hi");
    let screen = emu.snapshot();
    assert_eq!(screen.title, "my-title");
    assert_eq!(screen.to_lines()[0], "hi");
}

#[test]
fn cursor_hide_show() {
    let mut emu = Emulator::new(10, 2);
    emu.feed(b"\x1b[?25l");
    assert!(!emu.snapshot().cursor_visible);
    emu.feed(b"\x1b[?25h");
    assert!(emu.snapshot().cursor_visible);
}

#[test]
fn resize_changes_dimensions() {
    let mut emu = Emulator::new(20, 5);
    emu.feed(b"abc");
    emu.resize(10, 3);
    let screen = emu.snapshot();
    assert_eq!(screen.cols, 10);
    assert_eq!(screen.rows, 3);
    assert_eq!(screen.to_lines()[0], "abc");
}

#[test]
fn clear_screen() {
    let mut emu = Emulator::new(10, 3);
    emu.feed(b"junk\r\nmore");
    emu.feed(b"\x1b[2J\x1b[H");
    let screen = emu.snapshot();
    assert!(screen.to_lines().iter().all(|l| l.is_empty()), "screen cleared");
}
