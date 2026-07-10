//! Security target — the **client TTY emission** boundary. A malicious server's
//! `Screen` is re-encoded by the client through `new_frame` and the bytes are
//! written to the user's *real* terminal. Most of the screen is sanitized by
//! construction (the client rebuilds a minimal escape stream from structured
//! cells), but three fields are attacker-controlled strings emitted inside OSC
//! frames: the window **title** (OSC 0), an OSC 8 hyperlink **URI/id**, and the
//! **clipboard** (OSC 52, base64 — expected safe). If any of these can carry a
//! string terminator / ESC / control byte that breaks out of its OSC frame, the
//! following bytes are executed by the user's terminal — injection.
//!
//! Oracle: paint `new_frame(blank, screen)` into a fresh emulator (modelling the
//! real terminal) and assert the OSC field content did **not** bleed into the
//! visible grid, cursor, or terminal modes. The title/URI may be *sanitized*
//! (that's fine — we don't compare them); what must hold is that they can't
//! corrupt anything else.
//!
//! Run with: `cargo +nightly fuzz run tty_emission_safety`.
#![no_main]
use libfuzzer_sys::fuzz_target;
use mish_terminal::emulator::Emulator;
use mish_terminal::screen::{Hyperlink, Screen};

fn glyphs(s: &Screen) -> Vec<char> {
    s.cells.iter().map(|c| c.c).collect()
}

fn modes(s: &Screen) -> (bool, u8, bool, bool, bool) {
    (
        s.bracketed_paste,
        s.mouse_mode,
        s.alt_screen,
        s.app_cursor_keys,
        s.focus_event,
    )
}

fn lossy(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fuzz_target!(|data: &[u8]| {
    // A known, non-trivial base grid so any breakout that clears / moves / writes
    // is detectable as a glyph change.
    let (cols, rows) = (20u16, 3u16);
    let mut emu = Emulator::new(cols, rows);
    emu.feed(b"ABCDEFGHIJKLMNOPQRST");
    let mut screen = emu.snapshot();

    // Split the fuzz input three ways: title, clipboard, hyperlink target.
    let n = data.len();
    let (t, rest) = data.split_at(n / 3);
    let (c, u) = rest.split_at(rest.len() / 2);

    // Inject attacker-controlled OSC field content.
    screen.title = lossy(t);
    screen.clipboard = Some(lossy(c));
    if !screen.cells.is_empty() {
        screen.cells[0].hyperlink = Some(Hyperlink {
            id: Some(lossy(&u[..u.len() / 2])),
            uri: lossy(&u[u.len() / 2..]),
        });
    }

    // Emit to the real terminal (full repaint from blank) and re-read it.
    let frame = mish_terminal::new_frame(&Screen::blank(cols, rows), &screen, false, "");
    let mut real = Emulator::new(cols, rows);
    real.feed(&frame);
    let seen = real.snapshot();

    // The OSC field content must not have escaped into anything observable.
    assert_eq!(
        glyphs(&seen),
        glyphs(&screen),
        "OSC field content corrupted the visible grid (injection): title={:?} clip={:?}",
        screen.title,
        screen.clipboard
    );
    assert_eq!(
        (seen.cursor_row, seen.cursor_col),
        (screen.cursor_row, screen.cursor_col),
        "OSC field content moved the cursor (injection)"
    );
    assert_eq!(
        modes(&seen),
        modes(&screen),
        "OSC field content changed a terminal mode (injection)"
    );
});
