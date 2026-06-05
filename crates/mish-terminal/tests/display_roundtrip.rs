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
                focus_event: false,
                alternate_scroll: true,
                clipboard: None,
                app_cursor_keys: false,
                bell_count: 0,
            })
    })
}

/// A scrolling screen should diff to a small (scroll + a couple rows) frame, not
/// a full repaint, and still round-trip exactly.
#[test]
fn scroll_up_is_minimal_and_correct() {
    let cols = 20u16;
    let rows = 6u16;
    let line = |s: &str| -> Vec<Cell> {
        let mut row: Vec<Cell> = s
            .chars()
            .map(|c| Cell {
                c,
                ..Cell::default()
            })
            .collect();
        row.resize(cols as usize, Cell::default());
        row
    };
    let mk = |labels: [&str; 6]| -> Screen {
        let mut cells = Vec::new();
        for l in labels {
            cells.extend(line(l));
        }
        Screen {
            cols,
            rows,
            cells,
            cursor_row: rows - 1,
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
            clipboard: None,
            app_cursor_keys: false,
            bell_count: 0,
        }
    };
    let old = mk(["row0", "row1", "row2", "row3", "row4", "row5"]);
    // Scrolled up by 2: old rows 2..6 move to the top, two new rows at the bottom.
    let new = mk(["row2", "row3", "row4", "row5", "new6", "new7"]);

    let diff = new_frame(&old, &new, true);
    let full = new_frame(&Screen::blank(cols, rows), &new, false);
    assert!(
        diff.len() < full.len(),
        "scroll diff ({}) should be smaller than a full repaint ({})",
        diff.len(),
        full.len()
    );
    // Round-trips exactly.
    assert!(
        screen_eq(&apply(&old, &new), &new),
        "scroll diff must reproduce new"
    );
}

/// Focus-event mode (DECSET 1004) is captured by the emulator and round-trips
/// through the diff in both directions.
#[test]
fn focus_mode_roundtrips() {
    let mut emu = Emulator::new(10, 3);
    emu.feed(b"hi");
    let off0 = emu.snapshot();
    assert!(!off0.focus_event);
    emu.feed(b"\x1b[?1004h");
    let on = emu.snapshot();
    assert!(on.focus_event, "emulator tracks focus-event mode");
    assert!(apply(&off0, &on).focus_event, "1004 set round-trips");
    emu.feed(b"\x1b[?1004l");
    let off1 = emu.snapshot();
    assert!(!apply(&on, &off1).focus_event, "1004 reset round-trips");
}

/// Alternate-scroll mode (DECSET 1007) — default on in the emulator — round-trips.
#[test]
fn alternate_scroll_mode_roundtrips() {
    let mut emu = Emulator::new(10, 3);
    let on = emu.snapshot();
    assert!(on.alternate_scroll, "default on");
    emu.feed(b"\x1b[?1007l");
    let off = emu.snapshot();
    assert!(!off.alternate_scroll, "1007l turns it off");
    assert!(!apply(&on, &off).alternate_scroll, "reset round-trips");
    emu.feed(b"\x1b[?1007h");
    let on2 = emu.snapshot();
    assert!(apply(&off, &on2).alternate_scroll, "set round-trips");
}

/// Application-cursor-keys mode (DECCKM / DECSET 1) round-trips both ways — this
/// is what makes the client's arrow keys send the SS3 form inside vim/less.
#[test]
fn app_cursor_keys_roundtrips() {
    let mut emu = Emulator::new(10, 3);
    let off = emu.snapshot();
    assert!(!off.app_cursor_keys, "default off");
    emu.feed(b"\x1b[?1h");
    let on = emu.snapshot();
    assert!(on.app_cursor_keys, "DECSET 1 enables app cursor keys");
    assert!(apply(&off, &on).app_cursor_keys, "set round-trips");
    emu.feed(b"\x1b[?1l");
    let off2 = emu.snapshot();
    assert!(!apply(&on, &off2).app_cursor_keys, "reset round-trips");
}

/// Terminal bells are counted and the diff replays the delta as BEL bytes.
#[test]
fn bell_roundtrips() {
    let mut emu = Emulator::new(10, 2);
    let before = emu.snapshot();
    assert_eq!(before.bell_count, 0);
    emu.feed(b"\x07\x07"); // two beeps
    let after = emu.snapshot();
    assert_eq!(after.bell_count, 2, "emulator counts bells");
    // The diff carries exactly two BELs and reconstructs the count.
    let diff = new_frame(&before, &after, true);
    assert_eq!(diff.iter().filter(|&&b| b == 0x07).count(), 2, "delta BELs");
    assert_eq!(
        apply(&before, &after).bell_count,
        2,
        "bell count round-trips"
    );
}

/// OSC 52 clipboard is decoded by the emulator and re-emitted (base64) by the
/// diff, so the contents round-trip to the client.
#[test]
fn clipboard_osc52_roundtrips() {
    let mut emu = Emulator::new(10, 3);
    emu.feed(b"x");
    let before = emu.snapshot();
    assert_eq!(before.clipboard, None);
    // OSC 52 copy of "hello" (base64 "aGVsbG8="), ST-terminated.
    emu.feed(b"\x1b]52;c;aGVsbG8=\x1b\\");
    let set = emu.snapshot();
    assert_eq!(
        set.clipboard.as_deref(),
        Some("hello"),
        "emulator decodes the OSC 52 payload"
    );
    assert_eq!(
        apply(&before, &set).clipboard.as_deref(),
        Some("hello"),
        "clipboard round-trips through the diff"
    );
    // A subsequent change also propagates (base64("world")="d29ybGQ=").
    emu.feed(b"\x1b]52;c;d29ybGQ=\x1b\\");
    let changed = emu.snapshot();
    assert_eq!(
        apply(&set, &changed).clipboard.as_deref(),
        Some("world"),
        "clipboard change round-trips"
    );
}

/// Build a screen from one label per row (padded with blanks).
fn lines_to_screen(cols: u16, labels: &[&str]) -> Screen {
    let mut cells = Vec::new();
    for l in labels {
        let mut row: Vec<Cell> = l
            .chars()
            .map(|c| Cell {
                c,
                ..Cell::default()
            })
            .collect();
        row.resize(cols as usize, Cell::default());
        cells.extend(row);
    }
    Screen {
        cols,
        rows: labels.len() as u16,
        cells,
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
        clipboard: None,
        app_cursor_keys: false,
        bell_count: 0,
    }
}

/// Whole-screen downward scroll: emitted via reverse-index (RI), smaller than a
/// full repaint, and round-trips exactly.
#[test]
fn scroll_down_whole_screen() {
    let cols = 16u16;
    let old = lines_to_screen(cols, &["r0", "r1", "r2", "r3", "r4", "r5"]);
    // Scrolled down by 2: old rows 0..4 move to the bottom; two new top rows.
    let new = lines_to_screen(cols, &["t0", "t1", "r0", "r1", "r2", "r3"]);
    let diff = new_frame(&old, &new, true);
    let full = new_frame(&Screen::blank(cols, 6), &new, false);
    assert!(
        diff.windows(2).any(|w| w == b"\x1bM"),
        "downward scroll should emit reverse-index (RI)"
    );
    assert!(
        diff.len() < full.len(),
        "scroll diff smaller than full repaint"
    );
    assert!(
        screen_eq(&apply(&old, &new), &new),
        "down-scroll round-trips"
    );
}

/// Scroll region with a fixed bottom status line: rows [0,4] scroll up while the
/// last row stays. Emitted with DECSTBM and round-trips.
#[test]
fn scroll_region_bottom_status_fixed() {
    let cols = 20u16;
    let old = lines_to_screen(cols, &["a0", "a1", "a2", "a3", "a4", "STATUS"]);
    // Region [0,4] scrolled up by 1; row 5 (STATUS) unchanged.
    let new = lines_to_screen(cols, &["a1", "a2", "a3", "a4", "NEW", "STATUS"]);
    let diff = new_frame(&old, &new, true);
    let full = new_frame(&Screen::blank(cols, 6), &new, false);
    // DECSTBM set region "ESC[1;5r".
    assert!(
        diff.windows(6).any(|w| w == b"\x1b[1;5r"),
        "region scroll should set DECSTBM"
    );
    assert!(
        diff.len() < full.len(),
        "region scroll smaller than full repaint"
    );
    assert!(
        screen_eq(&apply(&old, &new), &new),
        "region up-scroll round-trips"
    );
}

/// Scroll region scrolling *down* with a fixed header and footer.
#[test]
fn scroll_region_down_with_fixed_header_footer() {
    let cols = 20u16;
    let old = lines_to_screen(cols, &["HDR", "b1", "b2", "b3", "b4", "FTR"]);
    // Region [1,4] scrolled down by 1; rows 0 and 5 unchanged.
    let new = lines_to_screen(cols, &["HDR", "NEW", "b1", "b2", "b3", "FTR"]);
    let diff = new_frame(&old, &new, true);
    assert!(
        diff.windows(6).any(|w| w == b"\x1b[2;5r"),
        "region [1,4] scroll should set DECSTBM ESC[2;5r"
    );
    assert!(
        diff.windows(2).any(|w| w == b"\x1bM"),
        "downward region scroll uses RI"
    );
    assert!(
        screen_eq(&apply(&old, &new), &new),
        "region down-scroll round-trips"
    );
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
        let old = Screen { cols, rows, cells: a_cells, cursor_row: ca.min(rows-1), cursor_col: cb.min(cols-1), cursor_visible: true, title: String::new(), echo_ack: 0, bracketed_paste: false, mouse_mode: 0, cursor_shape: 0, cursor_blink: false, focus_event: false, alternate_scroll: true, clipboard: None, app_cursor_keys: false, bell_count: 0 };
        let new = Screen { cols, rows, cells: b_cells, cursor_row: (rows-1).min(ca), cursor_col: (cols-1).min(cb), cursor_visible: false, title: String::new(), echo_ack: 0, bracketed_paste: false, mouse_mode: 0, cursor_shape: 0, cursor_blink: false, focus_event: false, alternate_scroll: true, clipboard: None, app_cursor_keys: false, bell_count: 0 };
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
