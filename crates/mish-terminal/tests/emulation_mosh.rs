//! Rust ports of mosh's terminal-emulation test suite
//! (`mosh/src/tests/emulation-*.test`), replaying the same escape sequences
//! into our alacritty-backed [`Emulator`] and asserting on the resulting
//! [`Screen`]. Where mosh asserts via tmux screen captures, we assert directly
//! on screen cells/cursor/attributes (the synchronized state).

use mish_ssp::state::SyncState;
use mish_terminal::emulator::Emulator;
use mish_terminal::screen::{Color, Screen};

fn run(cols: u16, rows: u16, seqs: &[&[u8]]) -> Screen {
    let mut e = Emulator::new(cols, rows);
    for s in seqs {
        e.feed(s);
    }
    e.snapshot()
}

/// emulation-80th-column: writing exactly 80 columns must NOT wrap to the next
/// line (VT100 deferred-wrap / "hidden 80th column"); the 81st char wraps.
#[test]
fn eightieth_column_deferred_wrap() {
    let mut e = Emulator::new(80, 24);
    e.feed(&[b'E'; 80]);
    let s = e.snapshot();
    assert_eq!(
        s.cursor_row, 0,
        "cursor stays on row 0 after exactly 80 columns"
    );
    assert_eq!(s.to_lines()[0].chars().filter(|&c| c == 'E').count(), 80);

    // The 81st character finally wraps to row 1.
    e.feed(b"X");
    assert_eq!(e.snapshot().cursor_row, 1, "81st column wraps");
}

/// emulation-cursor-motion: place characters with CUP (`ESC[<row>;<col>H`) and
/// verify each lands at its exact cell.
#[test]
fn cursor_motion_positions() {
    let positions: &[(u16, u16, char)] = &[
        (1, 1, 'A'),
        (10, 1, 'B'),
        (1, 2, 'C'),
        (1, 4, 'D'),
        (10, 4, 'E'),
        (1, 7, 'F'),
        (1, 11, 'G'),
        (10, 11, 'H'),
        (1, 16, 'I'),
        (2, 16, 'J'),
        (1, 22, 'K'),
        (60, 23, 'L'),
        (59, 23, 'M'),
        (57, 23, 'N'),
        (54, 23, 'O'),
        (50, 23, 'P'),
        (45, 23, 'Q'),
        (39, 23, 'R'),
        (32, 23, 'S'),
    ];
    let mut e = Emulator::new(80, 24);
    e.feed(b"\x1b[H\x1b[J");
    for (x, y, c) in positions {
        e.feed(format!("\x1b[{y};{x}H{c}").as_bytes());
    }
    let s = e.snapshot();
    for (x, y, c) in positions {
        assert_eq!(s.cell(y - 1, x - 1).unwrap().c, *c, "char {c} at ({x},{y})");
    }
}

/// emulation-scroll: Scroll Up (`ESC[<n>S`) discards the top n lines and shifts
/// the rest up.
#[test]
fn scroll_up() {
    let mut e = Emulator::new(80, 24);
    e.feed(b"\x1b[H\x1b[J");
    for i in 1..=24 {
        e.feed(format!("\x1b[{i};1Htext {i}").as_bytes());
    }
    e.feed(b"\x1b[4S"); // scroll up 4
    let s = e.snapshot();
    assert_eq!(s.to_lines()[0], "text 5", "top 4 lines scrolled off");
    assert_eq!(s.to_lines()[19], "text 24", "row 24 moved up by 4");
    assert!(
        s.to_lines()[20..].iter().all(|l| l.is_empty()),
        "exposed lines blank"
    );
}

/// emulation-back-tab: CBT (`ESC[<n>Z`, cursor backward tab) and CHT
/// (`ESC[<n>I`, cursor forward tab) with tab stops every 8 columns.
#[test]
fn back_tab_and_forward_tab() {
    let line0 = |seqs: &[&[u8]]| -> String {
        let mut v: Vec<&[u8]> = vec![b"\x1b[H\x1b[J", b"hello, wurld"];
        v.extend_from_slice(seqs);
        run(80, 24, &v).to_lines()[0].clone()
    };
    // cursor at col 12 → CBT 1 → col 8; 'o' overwrites the 'u'.
    assert_eq!(line0(&[b"\x1b[Z", b"o"]), "hello, world");
    // CBT 2 → col 0.
    assert_eq!(&line0(&[b"\x1b[2Z", b"o"])[..12], "oello, wurld");
    // CBT 99 clamps to col 0.
    assert_eq!(&line0(&[b"\x1b[99Z", b"9"])[..12], "9ello, wurld");
    // CHT 1 from col 12 → col 16; 't' there.
    assert_eq!(line0(&[b"\x1b[I", b"t"]), "hello, wurld    t");
    // CHT 99 clamps to the last column.
    let s = run(
        80,
        24,
        &[b"\x1b[H\x1b[J", b"hello, wurld", b"\x1b[99I", b"#"],
    );
    assert_eq!(
        s.cell(0, 79).unwrap().c,
        '#',
        "forward-tab clamps to last column"
    );
}

/// emulation-attributes-16color: SGR foreground colors (30–37) produce distinct
/// colors per cell.
#[test]
fn sgr_16_colors_distinct() {
    let s = run(20, 2, &[b"\x1b[31mR\x1b[32mG\x1b[34mB"]);
    let r = s.cell(0, 0).unwrap();
    let g = s.cell(0, 1).unwrap();
    let b = s.cell(0, 2).unwrap();
    assert_eq!((r.c, g.c, b.c), ('R', 'G', 'B'));
    assert!(matches!(r.fg, Color::Named(_)));
    assert_ne!(r.fg, g.fg);
    assert_ne!(g.fg, b.fg);
    assert_ne!(r.fg, b.fg);
}

/// emulation-attributes-bce: Background Color Erase — erasing the display after
/// setting a background color fills the erased cells with that background.
#[test]
fn background_color_erase() {
    let mut e = Emulator::new(20, 3);
    e.feed(b"\x1b[41mX"); // red background, write X at (0,0); cursor now (0,1)
    let red_bg = e.snapshot().cell(0, 0).unwrap().bg;
    assert_ne!(
        red_bg,
        Color::Named(mish_terminal::screen::NAMED_BACKGROUND)
    );
    // ESC[J (erase below) fills the rest of the cursor's line with the active
    // background color (BCE), as mosh's bce test relies on.
    e.feed(b"\x1b[J");
    let s = e.snapshot();
    assert_eq!(
        s.cell(0, 5).unwrap().bg,
        red_bg,
        "erased cells keep the bg color"
    );
}

/// emulation-attributes-256color & truecolor are covered by emulator_test.rs;
/// here we add the 256-color background path used by `bce`.
#[test]
fn indexed_256_background() {
    let s = run(10, 1, &[b"\x1b[48;5;32mZ"]);
    assert_eq!(s.cell(0, 0).unwrap().bg, Color::Indexed(32));
}

/// emulation-multiline-scroll: insert-line (`ESC[<n>L`) / delete-line
/// (`ESC[<n>M`) with assorted counts must not panic (regression for a crash).
#[test]
fn multiline_scroll_no_crash() {
    let mut e = Emulator::new(80, 24);
    e.feed(b"\x1b[H\x1b[J");
    for dir in ['L', 'M'] {
        for n in [0u32, 1, 2, 22, 23, 24, 25, 26] {
            e.feed(format!("{n}\r").as_bytes());
            e.feed(format!("\x1b[{n}{dir}").as_bytes());
        }
    }
    let _ = e.snapshot(); // reached here ⇒ no panic
}

/// emulation-wrap-across-frames: long lines that fill the width wrap to the next
/// row without corruption.
#[test]
fn wrap_across_rows() {
    let mut e = Emulator::new(80, 24);
    e.feed(b"\x1b[H\x1b[J");
    e.feed(&[b'A'; 80]);
    e.feed(&[b'B'; 80]);
    let s = e.snapshot();
    assert!(s.to_lines()[0].chars().all(|c| c == 'A'), "row 0 all A");
    assert!(
        s.to_lines()[1].chars().all(|c| c == 'B'),
        "row 1 all B (wrapped)"
    );
}

/// emulation-ascii-iso-8859: ASCII and Latin-1 high characters render.
#[test]
fn ascii_and_latin1() {
    // "café" with é as Latin-1 would need charset handling; use UTF-8 directly,
    // which is what modern locales feed.
    let s = run(20, 2, &["café ñ ü".as_bytes()]);
    assert_eq!(s.to_lines()[0], "café ñ ü");
}

/// unicode-combine-fallback-assert: a combining mark after `ESC[1J` must not
/// panic (mosh regression that previously hit an assertion).
#[test]
fn combining_after_erase_no_crash() {
    let s = run(20, 3, &[b"0\x1b[1J\xcc\xb4"]); // '0', erase-to-start, U+0334
    let _ = s.to_text();
}

/// unicode-later-combining: a combining circumflex (U+0302) in the stream is
/// handled; surrounding text survives.
#[test]
fn later_combining_survives() {
    let s = run(20, 4, &[b"abc\n\xcc\x82\ndef\n"]);
    assert_eq!(s.to_lines()[0], "abc");
    assert!(s.to_text().contains("def"));
}

/// network-no-diff: a sequence that returns the screen to its prior state
/// produces an empty diff (the server wouldn't send anything / wouldn't spin).
#[test]
fn no_op_sequence_yields_empty_diff() {
    let mut e = Emulator::new(20, 3);
    let before = e.snapshot();
    e.feed(b"x\x08 \x08"); // x, backspace, space (clears x), backspace
    let after = e.snapshot();
    assert!(
        after.diff_from(&before).is_empty(),
        "no-op sequence must not change the synchronized screen"
    );
}

/// emulation-attributes-osc8: hyperlinks are captured per cell and survive the
/// diff round-trip.
#[test]
fn osc8_hyperlink_captured_and_diffed() {
    let mut e = Emulator::new(20, 2);
    // OSC 8 link "ex" → https://example.com, then close.
    e.feed(b"\x1b]8;;https://example.com\x1b\\ex\x1b]8;;\x1b\\");
    let s = e.snapshot();
    let cell = s.cell(0, 0).unwrap();
    assert_eq!(cell.c, 'e');
    assert_eq!(
        cell.hyperlink.as_ref().map(|h| h.uri.as_str()),
        Some("https://example.com")
    );
    // The next char shares the link; the char after the close has none.
    assert!(s.cell(0, 1).unwrap().hyperlink.is_some());
    assert!(s.cell(0, 2).unwrap().hyperlink.is_none());

    // Round-trip through the diff (alacritty echoes the captured id verbatim).
    let blank = Screen::blank(20, 2);
    let mut e2 = Emulator::new(20, 2);
    e2.feed(&mish_terminal::display::new_frame(&blank, &s, false));
    assert_eq!(e2.snapshot(), s, "hyperlinks round-trip exactly");
}

/// Terminal modes (bracketed paste, mouse reporting, cursor style) are captured
/// and round-trip through the diff.
#[test]
fn terminal_modes_captured_and_diffed() {
    use mish_terminal::screen;
    let mut e = Emulator::new(10, 2);
    // Enable bracketed paste, SGR mouse + any-motion, and a steady beam cursor.
    e.feed(b"\x1b[?2004h\x1b[?1006h\x1b[?1003h\x1b[6 q");
    let s = e.snapshot();
    assert!(s.bracketed_paste);
    assert_ne!(s.mouse_mode & screen::MOUSE_SGR, 0);
    assert_ne!(s.mouse_mode & screen::MOUSE_MOTION, 0);
    assert_eq!(s.cursor_shape, screen::CURSOR_BEAM);
    assert!(!s.cursor_blink, "steady cursor");

    // Round-trip via the diff.
    let blank = Screen::blank(10, 2);
    let mut e2 = Emulator::new(10, 2);
    e2.feed(&mish_terminal::display::new_frame(&blank, &s, false));
    let s2 = e2.snapshot();
    assert_eq!(s2.bracketed_paste, s.bracketed_paste);
    assert_eq!(s2.mouse_mode, s.mouse_mode);
    assert_eq!(s2.cursor_shape, s.cursor_shape);
    assert_eq!(s2.cursor_blink, s.cursor_blink);
}

/// Combining marks are captured on the base cell and survive the new_frame diff.
#[test]
fn combining_marks_captured_and_diffed() {
    let mut e = Emulator::new(10, 2);
    e.feed("e\u{0301}".as_bytes()); // é = e + COMBINING ACUTE ACCENT
    let s = e.snapshot();
    let cell = s.cell(0, 0).unwrap();
    assert_eq!(cell.c, 'e');
    assert_eq!(cell.combining, vec!['\u{0301}']);

    // Round-trip through the minimal diff.
    let blank = Screen::blank(10, 2);
    let mut e2 = Emulator::new(10, 2);
    e2.feed(&mish_terminal::display::new_frame(&blank, &s, false));
    assert_eq!(
        e2.snapshot().cell(0, 0).unwrap().combining,
        vec!['\u{0301}']
    );
}

/// Wide (CJK) characters occupy a glyph cell + a spacer, and round-trip exactly.
#[test]
fn wide_char_cells_and_diff() {
    use mish_terminal::screen;
    let mut e = Emulator::new(10, 2);
    e.feed("世界".as_bytes());
    let s = e.snapshot();
    assert_eq!(s.cell(0, 0).unwrap().c, '世');
    assert_ne!(
        s.cell(0, 0).unwrap().flags & screen::F_WIDE,
        0,
        "wide flag set"
    );
    assert_ne!(
        s.cell(0, 1).unwrap().flags & screen::F_WIDE_SPACER,
        0,
        "spacer follows"
    );
    assert_eq!(s.cell(0, 2).unwrap().c, '界');

    let blank = Screen::blank(10, 2);
    let mut e2 = Emulator::new(10, 2);
    e2.feed(&mish_terminal::display::new_frame(&blank, &s, false));
    assert_eq!(e2.snapshot(), s, "wide chars round-trip exactly");
}

/// window-resize (emulation side): resizing reflows; content and dimensions
/// update without panic.
#[test]
fn resize_reflows() {
    let mut e = Emulator::new(80, 24);
    e.feed(b"\x1b[H\x1b[Jhello");
    e.resize(40, 10);
    let s = e.snapshot();
    assert_eq!((s.cols, s.rows), (40, 10));
    assert_eq!(s.to_lines()[0], "hello");
}
