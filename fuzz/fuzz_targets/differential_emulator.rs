//! Coverage-guided differential emulator fuzzing (review §B): drive our
//! alacritty-backed emulator AND an independent emulator (the `vt100` crate)
//! with the *same* VT byte stream and assert they render the same screen text +
//! cursor. This is the highest-value emulator-correctness lever — two unrelated
//! implementations must agree on what the bytes mean.
//!
//! The fuzz input is decoded into the same constrained grammar the
//! `differential_emulator` proptest uses — absolute positioning, printable runs,
//! erase-line, erase whole/below display, SGR — which is the common subset where
//! conforming emulators must agree. It excludes the documented divergences
//! (autowrap phantom column, tabs, scroll regions, wide-char width, and `CSI 1 J`
//! erase-above), keeping the equality assertion sound while letting libFuzzer's
//! coverage feedback explore the parser/grid far past proptest's random sampling.
//!
//! Run with: `cargo +nightly fuzz run differential_emulator`.
#![no_main]
use libfuzzer_sys::fuzz_target;
use mish_terminal::emulator::Emulator;

const ROWS: u16 = 10;
const COLS: u16 = 40;
const MAX_COL: u16 = 18;
const MAX_RUN: usize = 18;

/// Decode the fuzz bytes into a VT stream within the safe common-subset grammar.
fn build_vt(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0usize;
    // Bounds-safe read: yields 0 once the input is exhausted (the outer loop then
    // terminates). Never indexes out of range.
    let next = |i: &mut usize| -> u8 {
        let b = data.get(*i).copied().unwrap_or(0);
        *i += 1;
        b
    };
    while i < data.len() {
        match next(&mut i) % 4 {
            // Place: CUP to (row, col) then a printable run (kept short enough
            // that it can't reach the right margin → no autowrap divergence).
            0 => {
                let row = (next(&mut i) as u16) % ROWS;
                let col = (next(&mut i) as u16) % (MAX_COL + 1);
                out.extend_from_slice(format!("\x1b[{};{}H", row + 1, col + 1).as_bytes());
                let run = (next(&mut i) as usize) % (MAX_RUN + 1);
                for _ in 0..run {
                    let c = 0x20 + (next(&mut i) % 0x5f); // printable ASCII
                    out.push(c);
                }
            }
            // Erase in line (0=to-end, 1=to-start, 2=all) — all modes agree.
            1 => {
                out.extend_from_slice(format!("\x1b[{}K", next(&mut i) % 3).as_bytes());
            }
            // Erase in display: whole (2) or below cursor (0) only — NOT above
            // (1), which has a known alacritty/vt100 divergence.
            2 => {
                let m = if next(&mut i) % 2 == 0 { 0 } else { 2 };
                out.extend_from_slice(format!("\x1b[{m}J").as_bytes());
            }
            // SGR (changes attributes, not the text/cursor we compare).
            _ => {
                let codes = [0u8, 1, 4, 7, 31, 42];
                let m = codes[next(&mut i) as usize % codes.len()];
                out.extend_from_slice(format!("\x1b[{m}m").as_bytes());
            }
        }
    }
    out
}

fn vt100_lines(parser: &vt100::Parser) -> Vec<String> {
    let screen = parser.screen();
    (0..ROWS)
        .map(|r| {
            let mut s = String::new();
            for c in 0..COLS {
                match screen.cell(r, c) {
                    Some(cell) if !cell.contents().is_empty() => s.push_str(&cell.contents()),
                    _ => s.push(' '),
                }
            }
            s.trim_end().to_string()
        })
        .collect()
}

fuzz_target!(|data: &[u8]| {
    let bytes = build_vt(data);

    let mut ours = Emulator::new(COLS, ROWS); // (cols, rows)
    ours.feed(&bytes);
    let snap = ours.snapshot();

    let mut parser = vt100::Parser::new(ROWS, COLS, 0); // (rows, cols)
    parser.process(&bytes);

    assert_eq!(
        snap.to_lines(),
        vt100_lines(&parser),
        "rendered text diverged from vt100"
    );
    let (their_row, their_col) = parser.screen().cursor_position();
    assert_eq!(
        (snap.cursor_row, snap.cursor_col),
        (their_row, their_col),
        "cursor diverged from vt100"
    );
});
