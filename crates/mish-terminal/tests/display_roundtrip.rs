//! Verifies mosh's `new_frame` diff via round-trip identity: feeding the diff to
//! an emulator that currently shows `old` must reproduce `new` exactly. This is
//! the same self-check mosh's verbose mode performs.

use mish_terminal::display::new_frame;
use mish_terminal::emulator::Emulator;
use mish_terminal::screen::{Cell, Color, Screen};
use proptest::prelude::*;

/// Render `screen` into a fresh emulator (full repaint from blank) and snapshot.
fn paint(screen: &Screen) -> Screen {
    let mut emu = Emulator::new(screen.cols, screen.rows);
    let blank = Screen::blank(screen.cols, screen.rows);
    emu.feed(&new_frame(&blank, screen, false));
    emu.snapshot()
}

/// Apply an incremental diff: emulator shows `old`, feed new_frame(old,new).
fn apply(old: &Screen, new: &Screen) -> Screen {
    let mut emu = Emulator::new(old.cols, old.rows);
    let blank = Screen::blank(old.cols, old.rows);
    emu.feed(&new_frame(&blank, old, false));
    emu.feed(&new_frame(old, new, true));
    emu.snapshot()
}

/// Compare two screens for the fields new_frame is responsible for (ignores
/// echo_ack, which is out-of-band metadata).
fn screen_eq(a: &Screen, b: &Screen) -> bool {
    a.cols == b.cols
        && a.rows == b.rows
        && a.cells == b.cells
        && a.cursor_row == b.cursor_row
        && a.cursor_col == b.cursor_col
        && a.cursor_visible == b.cursor_visible
        && a.title == b.title
}

// Colors as the emulator actually produces them: the default sentinel is the
// foreground slot (256) for fg and the background slot (257) for bg — they never
// cross. The other variants (basic 0–15, indexed, rgb) are shared.
fn arb_color_with_default(default: u16) -> impl Strategy<Value = Color> {
    prop_oneof![
        Just(Color::Named(default)),
        (0u16..16).prop_map(Color::Named),
        any::<u8>().prop_map(Color::Indexed),
        (any::<u8>(), any::<u8>(), any::<u8>()).prop_map(|(r, g, b)| Color::Rgb(r, g, b)),
    ]
}

fn arb_cell() -> impl Strategy<Value = Cell> {
    // Printable ASCII + a few flags that round-trip cleanly through SGR.
    (
        prop::char::range(' ', '~'),
        arb_color_with_default(mish_terminal::screen::NAMED_FOREGROUND),
        arb_color_with_default(mish_terminal::screen::NAMED_BACKGROUND),
        prop_oneof![Just(0u16), Just(2u16), Just(4u16), Just(8u16), Just(6u16)],
    )
        .prop_map(|(c, fg, bg, flags)| Cell {
            c,
            fg,
            bg,
            flags,
            combining: Vec::new(),
            hyperlink: None,
        })
}

fn arb_screen() -> impl Strategy<Value = Screen> {
    (4u16..16, 2u16..8).prop_flat_map(|(cols, rows)| {
        let n = cols as usize * rows as usize;
        (
            Just(cols),
            Just(rows),
            prop::collection::vec(arb_cell(), n),
            0u16..rows,
            0u16..cols,
            any::<bool>(),
        )
            .prop_map(|(cols, rows, cells, cr, cc, cv)| Screen {
                cols,
                rows,
                cells,
                cursor_row: cr,
                cursor_col: cc,
                cursor_visible: cv,
                title: String::new(),
                echo_ack: 0,
                bracketed_paste: false,
                mouse_mode: 0,
                cursor_shape: 0,
                cursor_blink: false,
            })
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(400))]

    /// A full repaint reproduces the screen exactly.
    #[test]
    fn full_repaint_roundtrips(s in arb_screen()) {
        let got = paint(&s);
        if !screen_eq(&got, &s) {
            let firstdiff = (0..s.cells.len()).find(|&i| got.cells.get(i) != s.cells.get(i));
            prop_assert!(false, "paint mismatch: dims got({},{}) want({},{}); cur got({},{},{}) want({},{},{}); firstdiff cell {:?}: got={:?} want={:?}",
                got.cols, got.rows, s.cols, s.rows,
                got.cursor_row, got.cursor_col, got.cursor_visible, s.cursor_row, s.cursor_col, s.cursor_visible,
                firstdiff, firstdiff.map(|i| &got.cells[i]), firstdiff.map(|i| &s.cells[i]));
        }
    }

    /// An incremental diff between two same-size screens reproduces `new`.
    #[test]
    fn incremental_diff_roundtrips(
        (cols, rows) in (4u16..16, 2u16..8),
        cells_a in prop::collection::vec(arb_cell(), 4*2..16*8),
        cells_b in prop::collection::vec(arb_cell(), 4*2..16*8),
        ca in 0u16..8, cb in 0u16..16,
    ) {
        let n = cols as usize * rows as usize;
        let mut a_cells = cells_a; a_cells.resize(n, Cell::default());
        let mut b_cells = cells_b; b_cells.resize(n, Cell::default());
        let old = Screen { cols, rows, cells: a_cells, cursor_row: ca.min(rows-1), cursor_col: cb.min(cols-1), cursor_visible: true, title: String::new(), echo_ack: 0, bracketed_paste: false, mouse_mode: 0, cursor_shape: 0, cursor_blink: false };
        let new = Screen { cols, rows, cells: b_cells, cursor_row: (rows-1).min(ca), cursor_col: (cols-1).min(cb), cursor_visible: false, title: String::new(), echo_ack: 0, bracketed_paste: false, mouse_mode: 0, cursor_shape: 0, cursor_blink: false };
        let got = apply(&old, &new);
        if !screen_eq(&got, &new) {
            let fd = (0..new.cells.len()).find(|&i| got.cells.get(i) != new.cells.get(i));
            prop_assert!(false, "incremental mismatch: cur got({},{}) want({},{}); firstdiff {:?} got={:?} want={:?}; diff={:?}",
                got.cursor_row, got.cursor_col, new.cursor_row, new.cursor_col,
                fd, fd.map(|i| &got.cells[i]), fd.map(|i| &new.cells[i]),
                String::from_utf8_lossy(&new_frame(&old, &new, true)));
        }
    }

    /// Identical screens diff to (essentially) nothing — no spurious changes.
    #[test]
    fn identical_screens_no_change(s in arb_screen()) {
        let painted = paint(&s);
        let diff = new_frame(&painted, &painted, true);
        prop_assert!(diff.is_empty(), "identical screens produced a non-empty diff: {:?}", String::from_utf8_lossy(&diff));
    }
}
