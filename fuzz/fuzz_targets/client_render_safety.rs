//! Security target — the **full client render path** a regular user runs. A
//! malicious/compromised server sends an arbitrary wire diff; the client
//! reconstructs a `Screen` from it (`apply_diff`) and repaints that screen to the
//! user's *real* terminal (`new_frame`). This drives the whole chain end-to-end
//! and asserts the bytes the client writes to the real TTY reproduce *exactly*
//! the screen it reconstructed — i.e. nothing the server put in the diff (glyphs,
//! cursor, modes, or OSC title/clipboard/hyperlink) escapes `new_frame`'s framing
//! to drive the user's terminal on its own. A divergence is a client-side
//! terminal injection, the "honest user gets hacked by the host" threat.
//!
//! Complements `tty_emission_safety` (which targets the OSC fields against a
//! fixed grid): this runs an *arbitrary server escape stream* through
//! `apply_diff` → `new_frame` → a real terminal.
//!
//! Run with: `cargo +nightly fuzz run client_render_safety`.
#![no_main]
use libfuzzer_sys::fuzz_target;
use mish_ssp::state::SyncState;
use mish_terminal::emulator::Emulator;
use mish_terminal::new_frame;
use mish_terminal::screen::Screen;

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

fuzz_target!(|data: &[u8]| {
    let (cols, rows) = (24u16, 4u16);

    // Reconstruct the screen the client gets from a hostile server wire diff:
    // a valid header (dims >= 2) followed by the fuzz bytes as the server's
    // escape stream. This is the same path `Screen::apply_diff` runs on the wire.
    let mut diff = Vec::new();
    diff.extend_from_slice(&0u64.to_le_bytes()); // echo_ack
    diff.extend_from_slice(&cols.to_le_bytes());
    diff.extend_from_slice(&rows.to_le_bytes());
    diff.push(0); // flags
    diff.extend_from_slice(data); // arbitrary server-controlled escape stream

    let mut reconstructed = Screen::blank(cols, rows);
    reconstructed.apply_diff(&diff);

    // The client repaints it to the user's real terminal.
    let frame = new_frame(&Screen::blank(cols, rows), &reconstructed, false);
    let mut real = Emulator::new(cols, rows);
    real.feed(&frame);
    let seen = real.snapshot();

    // The real terminal shows exactly what the client reconstructed — nothing the
    // server supplied broke out of the rendering to drive the terminal itself.
    // (Title/clipboard may be *sanitized* on emit, so we compare the observable
    // grid/cursor/modes, where an injection would show up.)
    assert_eq!(
        glyphs(&seen),
        glyphs(&reconstructed),
        "client emission diverged from the reconstructed screen — terminal injection"
    );
    assert_eq!(
        (seen.cursor_row, seen.cursor_col),
        (reconstructed.cursor_row, reconstructed.cursor_col),
        "client emission moved the cursor — terminal injection"
    );
    assert_eq!(
        modes(&seen),
        modes(&reconstructed),
        "client emission changed a terminal mode — terminal injection"
    );
});
