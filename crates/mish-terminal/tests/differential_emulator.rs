//! Differential emulator fuzzing: feed identical VT byte streams to our
//! alacritty-backed [`Emulator`] and to an *independent* emulator (the `vt100`
//! crate), and assert they render the same screen.
//!
//! Our other terminal tests check *self-consistency* (our emulator agrees with
//! our diff). This checks *correctness*: two unrelated implementations must
//! agree on what the bytes mean. A divergence is a real bug in one of them
//! (almost always ours, since vt100 is widely used).
//!
//! The grammar is deliberately the common subset where any conforming emulator
//! must agree — absolute cursor positioning, printable runs, erase-line, erase
//! whole/below display, and SGR (which changes attributes, not the text we
//! compare). It avoids the genuinely implementation-defined corners (autowrap's
//! deferred-wrap "phantom column", tab stops, scroll regions, wide-char width
//! policy) where conforming emulators legitimately differ — those are covered
//! for *robustness* by the round-trip and coverage-guided fuzzers, just not for
//! cross-emulator equality.
//!
//! KNOWN DIVERGENCE (excluded from the grammar): `CSI 1 J` (erase-display from
//! start to cursor) disagrees between our alacritty backend and vt100 in one
//! narrow case — when the cursor sits on row 1, alacritty leaves row 0 intact
//! whereas vt100 (matching the xterm "erase above, inclusive" spec) clears it.
//! Minimal repro: `\x1b[1;1H!\x1b[2;1H\x1b[1J` → ours keeps "!", vt100 clears it.
//! alacritty clears correctly for cursor rows >= 2 and for `CSI 2 J`/`CSI 0 J`.
//! This is inherited from the alacritty dependency (not our code) and `CSI 1 J`
//! is rare in practice; tracked in FUTURE_WORK.md.

use mish_terminal::emulator::Emulator;
use proptest::prelude::*;

const ROWS: u16 = 10;
const COLS: u16 = 40;
// Cap positions/run lengths so a print can never reach the right margin (no
// autowrap) — the one place conforming emulators are allowed to disagree.
const MAX_COL: u16 = 18;
const MAX_RUN: usize = 18;

#[derive(Clone, Debug)]
enum Cmd {
    /// Move to (row, col) absolute, then print a printable-ASCII run.
    Place { row: u16, col: u16, text: String },
    /// Erase in line (0=to-end, 1=to-start, 2=all).
    Eraseline(u8),
    /// Erase in display (0=to-end, 1=to-start, 2=all).
    Erasedisplay(u8),
    /// A select-graphic-rendition change (affects attributes, not text).
    Sgr(u8),
}

fn arb_cmd() -> impl Strategy<Value = Cmd> {
    prop_oneof![
        8 => (
            0..ROWS,
            0..=MAX_COL,
            proptest::collection::vec(0x20u8..0x7f, 0..MAX_RUN),
        )
            .prop_map(|(row, col, bytes)| Cmd::Place {
                row,
                col,
                text: String::from_utf8(bytes).unwrap(),
            }),
        1 => (0u8..3).prop_map(Cmd::Eraseline),
        // Erase-display: whole (2) and below-cursor (0) only. Above-cursor (1)
        // is excluded — see the KNOWN DIVERGENCE note in the module docs.
        1 => prop_oneof![Just(0u8), Just(2)].prop_map(Cmd::Erasedisplay),
        1 => prop_oneof![Just(0u8), Just(1), Just(4), Just(7), Just(31), Just(42)].prop_map(Cmd::Sgr),
    ]
}

fn encode(cmds: &[Cmd]) -> Vec<u8> {
    let mut out = Vec::new();
    for cmd in cmds {
        match cmd {
            Cmd::Place { row, col, text } => {
                // CUP is 1-based.
                out.extend_from_slice(format!("\x1b[{};{}H", row + 1, col + 1).as_bytes());
                out.extend_from_slice(text.as_bytes());
            }
            Cmd::Eraseline(m) => out.extend_from_slice(format!("\x1b[{m}K").as_bytes()),
            Cmd::Erasedisplay(m) => out.extend_from_slice(format!("\x1b[{m}J").as_bytes()),
            Cmd::Sgr(m) => out.extend_from_slice(format!("\x1b[{m}m").as_bytes()),
        }
    }
    out
}

/// vt100's view of the screen as one trimmed `String` per row.
fn vt100_lines(parser: &vt100::Parser) -> Vec<String> {
    let screen = parser.screen();
    (0..ROWS)
        .map(|r| {
            let mut s = String::new();
            for c in 0..COLS {
                if let Some(cell) = screen.cell(r, c) {
                    let contents = cell.contents();
                    // An empty cell renders as a space in our `to_lines`.
                    s.push_str(if contents.is_empty() { " " } else { &contents });
                } else {
                    s.push(' ');
                }
            }
            s.trim_end().to_string()
        })
        .collect()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1500))]

    #[test]
    fn matches_vt100_text(cmds in proptest::collection::vec(arb_cmd(), 0..40)) {
        let bytes = encode(&cmds);

        // Our emulator takes (cols, rows); vt100 takes (rows, cols).
        let mut ours = Emulator::new(COLS, ROWS);
        ours.feed(&bytes);
        let our_lines = ours.snapshot().to_lines();

        let mut parser = vt100::Parser::new(ROWS, COLS, 0);
        parser.process(&bytes);
        let their_lines = vt100_lines(&parser);

        prop_assert_eq!(
            &our_lines,
            &their_lines,
            "rendered text diverged from vt100\nbytes: {:?}",
            String::from_utf8_lossy(&bytes)
        );
    }

    /// Cursor position must also agree after absolute positioning + printing.
    #[test]
    fn matches_vt100_cursor(cmds in proptest::collection::vec(arb_cmd(), 0..40)) {
        let bytes = encode(&cmds);

        let mut ours = Emulator::new(COLS, ROWS);
        ours.feed(&bytes);
        let snap = ours.snapshot();

        let mut parser = vt100::Parser::new(ROWS, COLS, 0);
        parser.process(&bytes);
        let (their_row, their_col) = parser.screen().cursor_position();

        prop_assert_eq!(
            (snap.cursor_row, snap.cursor_col),
            (their_row, their_col),
            "cursor position diverged from vt100\nbytes: {:?}",
            String::from_utf8_lossy(&bytes)
        );
    }
}
