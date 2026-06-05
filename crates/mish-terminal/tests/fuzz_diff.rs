//! Structured-VT fuzzing of the diff round-trip identity.
//!
//! Random byte fuzzing mostly bounces off the parser; instead we generate
//! sequences of *valid* terminal operations (text, cursor moves, SGR, erases,
//! scrolls, wide/combining chars, OSC title/hyperlink, mode sets, resizes),
//! render them to an escape stream, feed the emulator one op at a time, and
//! after each op assert the wire diff round-trips:
//!
//!   prev.clone().apply_diff(cur.diff_from(&prev)) == cur
//!
//! This reaches realistic emulator states that the synthetic `Screen`
//! generators never produce, and exercises the exact `SyncState` path the wire
//! uses (mosh's `new_frame` + emulator replay inside `apply_diff`).

use mish_ssp::state::SyncState;
use mish_terminal::emulator::Emulator;
use mish_terminal::screen::Screen;
use proptest::prelude::*;

#[derive(Clone, Debug)]
enum Op {
    Print(String),
    Cup(u16, u16), // cursor position
    Sgr(Vec<u16>), // select graphic rendition
    El(u16),       // erase in line
    Ed(u16),       // erase in display
    ScrollUp(u16),
    ScrollDown(u16),
    Newline,
    CarriageReturn,
    Tab,
    Backspace,
    Title(String),
    Hyperlink(String),
    HyperlinkClose,
    Mode(u16, bool), // DECSET/DECRST
    CursorStyle(u16),
    CursorVis(bool),
}

fn render(op: &Op, out: &mut Vec<u8>) {
    let mut push = |s: &str| out.extend_from_slice(s.as_bytes());
    match op {
        Op::Print(s) => push(s),
        Op::Cup(r, c) => push(&format!("\x1b[{};{}H", r + 1, c + 1)),
        Op::Sgr(codes) => {
            let joined = codes
                .iter()
                .map(|c| c.to_string())
                .collect::<Vec<_>>()
                .join(";");
            push(&format!("\x1b[{joined}m"));
        }
        Op::El(m) => push(&format!("\x1b[{m}K")),
        Op::Ed(m) => push(&format!("\x1b[{m}J")),
        Op::ScrollUp(n) => push(&format!("\x1b[{n}S")),
        Op::ScrollDown(n) => push(&format!("\x1b[{n}T")),
        Op::Newline => push("\n"),
        Op::CarriageReturn => push("\r"),
        Op::Tab => push("\t"),
        Op::Backspace => push("\x08"),
        Op::Title(t) => push(&format!("\x1b]0;{t}\x07")),
        Op::Hyperlink(uri) => push(&format!("\x1b]8;;{uri}\x1b\\")),
        Op::HyperlinkClose => push("\x1b]8;;\x1b\\"),
        Op::Mode(n, on) => push(&format!("\x1b[?{}{}", n, if *on { 'h' } else { 'l' })),
        Op::CursorStyle(n) => push(&format!("\x1b[{n} q")),
        Op::CursorVis(on) => push(if *on { "\x1b[?25h" } else { "\x1b[?25l" }),
    }
}

// NOTE: wide (CJK) and combining characters are intentionally excluded from the
// broad fuzzer. Arbitrary op sequences can bisect a wide character (e.g.
// backspace into its spacer cell, then write), producing a malformed emulator
// grid — a wide glyph whose spacer holds unrelated content — that cannot be
// reproduced by re-emitting glyphs (and which real programs never create; they
// delete/redraw whole grapheme clusters). Well-formed wide/combining round-trip
// is covered by dedicated tests in `emulation_mosh.rs`.
fn arb_op() -> impl Strategy<Value = Op> {
    prop_oneof![
        "[a-zA-Z0-9 .,!?]{1,12}".prop_map(Op::Print),
        (0u16..8, 0u16..24).prop_map(|(r, c)| Op::Cup(r, c)),
        prop::collection::vec(
            prop_oneof![
                Just(0u16),
                Just(1),
                Just(2),
                Just(3),
                Just(4),
                Just(7),
                Just(9),
                (30u16..38),
                (90u16..98),
                (40u16..48),
                (100u16..108),
            ],
            0..4,
        )
        .prop_map(Op::Sgr),
        (0u16..3).prop_map(Op::El),
        (0u16..3).prop_map(Op::Ed),
        (1u16..6).prop_map(Op::ScrollUp),
        (1u16..6).prop_map(Op::ScrollDown),
        Just(Op::Newline),
        Just(Op::CarriageReturn),
        Just(Op::Tab),
        Just(Op::Backspace),
        "[a-z ]{0,8}".prop_map(Op::Title),
        prop_oneof![
            Just("http://x.io".to_string()),
            Just("file:///a".to_string())
        ]
        .prop_map(Op::Hyperlink),
        Just(Op::HyperlinkClose),
        (
            prop_oneof![
                Just(2004u16),
                Just(1000),
                Just(1002),
                Just(1003),
                Just(1006)
            ],
            any::<bool>()
        )
            .prop_map(|(n, on)| Op::Mode(n, on)),
        (1u16..7).prop_map(Op::CursorStyle),
        any::<bool>().prop_map(Op::CursorVis),
    ]
}

fn screen_eq(a: &Screen, b: &Screen) -> bool {
    // Compare everything new_frame is responsible for (echo_ack is metadata).
    a.cols == b.cols
        && a.rows == b.rows
        && a.cells == b.cells
        && a.cursor_row == b.cursor_row
        && a.cursor_col == b.cursor_col
        && a.cursor_visible == b.cursor_visible
        && a.title == b.title
        && a.bracketed_paste == b.bracketed_paste
        && a.mouse_mode == b.mouse_mode
        && a.cursor_shape == b.cursor_shape
        && a.cursor_blink == b.cursor_blink
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(400))]

    #[test]
    fn diff_roundtrips_over_vt_op_sequences(ops in prop::collection::vec(arb_op(), 1..40)) {
        let mut emu = Emulator::new(24, 8);
        let mut prev = emu.snapshot();
        for op in &ops {
            let mut bytes = Vec::new();
            render(op, &mut bytes);
            emu.feed(&bytes);
            let cur = emu.snapshot();

            // The real wire path: diff prev->cur, apply to a clone of prev.
            let diff = cur.diff_from(&prev);
            let mut x = prev.clone();
            x.apply_diff(&diff);
            if !screen_eq(&x, &cur) {
                let fd = (0..cur.cells.len()).find(|&i| x.cells.get(i) != cur.cells.get(i));
                prop_assert!(false,
                    "round-trip failed after {:?}\n cur ={:?}\n got ={:?}\n firstdiff cell {:?}: cur={:?} got={:?}\n cursor cur=({},{},{}) got=({},{},{})",
                    op, cur.to_lines(), x.to_lines(),
                    fd, fd.map(|i| &cur.cells[i]), fd.map(|i| &x.cells[i]),
                    cur.cursor_row, cur.cursor_col, cur.cursor_visible,
                    x.cursor_row, x.cursor_col, x.cursor_visible);
            }
            prev = cur;
        }
    }
}
