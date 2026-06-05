//! Real-terminal reference harness (#39): feed the output of a *real program*
//! running on a *real kernel PTY* to both our alacritty-backed [`Emulator`] and
//! an independent reference emulator (the `vt100` crate), and assert they render
//! the same screen.
//!
//! How this differs from the sibling terminal tests:
//! - `mish-terminal/tests/differential_emulator.rs` cross-checks against vt100
//!   but feeds a *synthetic* VT grammar we generate.
//! - `mosh/tests/replay.rs` replays *real* shell output but only checks our own
//!   diff round-trip (self-consistency), not an independent renderer.
//!
//! This one closes the gap: the bytes come from a real `/bin/sh` writing through
//! a real PTY line discipline (so they include whatever escape encoding the tool
//! and kernel actually produce), and the oracle is an unrelated emulator. A
//! divergence is a real rendering bug. The script stays inside the
//! conforming-emulator subset (absolute positioning, printable runs, erase) and
//! away from the margins, where autowrap/tab/wide-char policy is allowed to
//! differ (see the differential test's notes).
//!
//! (A fuller "real terminal" oracle — driving tmux/xterm and diffing its pane —
//! is the natural next step where those are installed; vt100 is the portable,
//! always-available independent renderer used here.)

use std::time::Duration;

use mish::pty::PtyProcess;
use mish_terminal::emulator::Emulator;
use tokio::time::timeout;

const COLS: u16 = 40;
const ROWS: u16 = 10;

/// vt100's rendered screen as one trailing-trimmed `String` per row (matching
/// how our `Screen::to_lines` trims).
fn vt100_lines(parser: &vt100::Parser) -> Vec<String> {
    let screen = parser.screen();
    (0..ROWS)
        .map(|r| {
            let mut s = String::new();
            for c in 0..COLS {
                let contents = screen.cell(r, c).map(|cell| cell.contents()).unwrap_or_default();
                // An empty cell renders as a space, matching `Screen::to_lines`.
                s.push_str(if contents.is_empty() { " " } else { contents });
            }
            s.trim_end().to_string()
        })
        .collect()
}

/// Run `script` under `/bin/sh -c` on a real PTY and collect everything it
/// writes (until the child exits and the master sees EOF).
async fn run_on_pty(script: &str) -> Vec<u8> {
    let mut pty = PtyProcess::spawn_argv(
        vec!["/bin/sh".into(), "-c".into(), script.into()],
        COLS,
        ROWS,
    )
    .expect("spawn /bin/sh on a PTY");

    let mut out = Vec::new();
    // Drain until the channel closes (reader thread hit EOF after the child
    // exited). A timeout guards against a hang.
    let _ = timeout(Duration::from_secs(10), async {
        while let Some(chunk) = pty.output.recv().await {
            out.push(chunk);
        }
    })
    .await;
    out.concat()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_pty_output_matches_vt100() {
    // A deterministic program emitting genuine VT sequences: clear, absolute
    // cursor moves, printable runs, an erase-to-end-of-line, and SGR (which
    // changes attributes, not the text we compare). No trailing newline, so the
    // PTY's NL→CRNL output translation never enters the picture.
    let script = "printf '\\033[2J\\033[2;3HHELLO WORLD\\033[4;1Habcdefghij\\033[4;6K\
                  \\033[6;5H[mish]\\033[1m\\033[8;2HBOLD-TEXT\\033[0m'";

    let bytes = run_on_pty(script).await;
    assert!(!bytes.is_empty(), "the program produced no output");

    let mut ours = Emulator::new(COLS, ROWS);
    ours.feed(&bytes);
    let our_lines = ours.snapshot().to_lines();

    let mut parser = vt100::Parser::new(ROWS, COLS, 0);
    parser.process(&bytes);
    let their_lines = vt100_lines(&parser);

    assert_eq!(
        our_lines,
        their_lines,
        "our emulator and vt100 rendered real PTY output differently\nbytes: {:?}",
        String::from_utf8_lossy(&bytes)
    );
    // Sanity: the content actually rendered (the harness isn't trivially passing
    // on two blank screens).
    assert!(
        our_lines.iter().any(|l| l.contains("HELLO WORLD")),
        "expected rendered content, got: {our_lines:?}"
    );
}
