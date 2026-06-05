//! Real-program replay: drive a real shell on a PTY, run programs that emit
//! genuine terminal output (color, cursor motion, clears, scrolling), and assert
//! the diff round-trip identity on the resulting screens after every output
//! chunk. The invariant is content-agnostic, so the programs' (non-deterministic)
//! output is fine — we only check that the diff faithfully reproduces each
//! screen transition on realistic input.

use std::time::Duration;

use mish::pty::PtyProcess;
use mish::server::PtyControl;
use mish_ssp::state::SyncState;
use mish_terminal::emulator::Emulator;
use mish_terminal::screen::Screen;

fn screen_eq(a: &Screen, b: &Screen) -> bool {
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_shell_output_diff_roundtrips() {
    let mut pty = PtyProcess::spawn("/bin/sh", 80, 24).expect("spawn shell");

    // A script exercising color, cursor motion, erases, scrolling, and a wide
    // glyph — then a sentinel so we know when to stop.
    let script = r#"
printf '\033[1;31mred\033[0m \033[42mgreenbg\033[0m\n'
printf '\033[2J\033[Hcleared screen\n'
printf '\033[5;10Hpositioned\n'
seq 1 60 2>/dev/null | tail -30
ls --color=always -la / 2>/dev/null | head -20
printf 'wide: 世界 \xc3\xa9\n'
printf '\033[3Sscrolled\n'
echo __REPLAY_DONE__
exit
"#;
    pty.control
        .send(PtyControl::Input(script.as_bytes().to_vec()))
        .unwrap();

    let mut emu = Emulator::new(80, 24);
    let mut prev = emu.snapshot();
    let mut chunks = 0usize;

    let done = tokio::time::timeout(Duration::from_secs(20), async {
        let mut saw_sentinel = false;
        while let Some(bytes) = pty.output.recv().await {
            emu.feed(&bytes);
            let cur = emu.snapshot();
            // The real wire diff must reproduce this transition exactly.
            let diff = cur.diff_from(&prev);
            let mut x = prev.clone();
            x.apply_diff(&diff);
            assert!(
                screen_eq(&x, &cur),
                "diff round-trip failed on real shell output (chunk {chunks})\n cur={:?}\n got={:?}",
                cur.to_lines(),
                x.to_lines()
            );
            prev = cur;
            chunks += 1;
            if emu.snapshot().to_text().contains("__REPLAY_DONE__") {
                saw_sentinel = true;
                break;
            }
        }
        saw_sentinel
    })
    .await
    .expect("replay completed in time");

    assert!(done, "saw the sentinel");
    assert!(chunks > 0, "processed some output");
}
