//! Diff-engine throughput benchmark — the Rust counterpart to mosh's
//! `src/tests/benchmark.cc`, which times the cost of computing the minimal
//! screen update (mosh's `Display::new_frame`) and applying it.
//!
//! Run it (release is essential — a debug build is ~20× slower and meaningless):
//!
//! ```sh
//! cargo run -p mish-terminal --release --example diff_bench
//! ```
//!
//! It reports, for a few representative workloads, how many frame-diffs per
//! second the engine sustains and the average wire size of each diff — the hot
//! loop that runs once per received screen on the client and once per emitted
//! frame on the server.

use std::time::Instant;

use mish_ssp::state::SyncState;
use mish_terminal::display::new_frame;
use mish_terminal::emulator::Emulator;
use mish_terminal::screen::Screen;

const COLS: u16 = 80;
const ROWS: u16 = 24;

/// Build a sequence of `n` successive screens from an emulator driven by
/// `step(i)` bytes — i.e. a realistic stream of incremental terminal updates.
fn frames<F: Fn(usize) -> Vec<u8>>(n: usize, step: F) -> Vec<Screen> {
    let mut emu = Emulator::new(COLS, ROWS);
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        emu.feed(&step(i));
        out.push(emu.snapshot());
    }
    out
}

/// Time `rounds` passes over consecutive (prev → cur) diffs, returning
/// (diffs_per_sec, avg_diff_bytes, reconstruct_ok).
fn bench(name: &str, screens: &[Screen], rounds: usize) {
    assert!(screens.len() >= 2);

    // --- new_frame: compute the minimal update between consecutive screens. ---
    let mut total_bytes = 0usize;
    let mut count = 0usize;
    let t0 = Instant::now();
    for _ in 0..rounds {
        for w in screens.windows(2) {
            let diff = new_frame(&w[0], &w[1], true, "");
            total_bytes += diff.len();
            count += 1;
            std::hint::black_box(&diff);
        }
    }
    let diff_elapsed = t0.elapsed();
    let diffs_per_sec = count as f64 / diff_elapsed.as_secs_f64();
    let avg_bytes = total_bytes as f64 / count as f64;
    let cells_per_sec = diffs_per_sec * (COLS as f64 * ROWS as f64);

    // --- apply_diff round-trip: reconstruct cur from prev + the SyncState diff,
    //     replayed through a throwaway emulator (the client's paint path). ---
    let mut ok = true;
    let t1 = Instant::now();
    let mut applies = 0usize;
    for _ in 0..rounds {
        for w in screens.windows(2) {
            let wire = w[1].diff_from(&w[0]);
            let mut reconstructed = w[0].clone();
            reconstructed.apply_diff(&wire);
            ok &= reconstructed == w[1];
            applies += 1;
            std::hint::black_box(&reconstructed);
        }
    }
    let apply_elapsed = t1.elapsed();
    let applies_per_sec = applies as f64 / apply_elapsed.as_secs_f64();

    println!("{name}:");
    println!(
        "  new_frame : {diffs_per_sec:>10.0} diffs/s   {cells_per_sec:>12.0} cells/s   \
         avg {avg_bytes:>6.1} B/diff"
    );
    println!(
        "  apply     : {applies_per_sec:>10.0} applies/s  round-trip {}",
        if ok { "OK" } else { "MISMATCH" }
    );
    assert!(ok, "diff round-trip must reconstruct the screen exactly");
}

fn main() {
    println!("mish diff-engine benchmark ({COLS}x{ROWS})\n");

    // 1. Scrolling build log: one new line per frame (the common case — a
    //    streaming command whose output scrolls).
    let scroll = frames(400, |i| {
        format!("[{i:05}] build step {i} {}\r\n", "=".repeat((i * 7) % 60)).into_bytes()
    });
    bench("scrolling log (1 line/frame)", &scroll, 200);

    // 2. Single-cell typing: each frame changes one character (predictive-echo /
    //    interactive shell), the cheapest realistic diff.
    let typing = frames(400, |i| {
        let col = (i % (COLS as usize - 1)) + 1;
        format!("\x1b[12;{col}H{}", (b'a' + (i % 26) as u8) as char).into_bytes()
    });
    bench("interactive typing (1 cell/frame)", &typing, 400);

    // 3. Full repaints: alternate between two completely different screens (a
    //    full-screen TUI redraw / `clear` + repaint), the worst case.
    let heavy = frames(120, |i| {
        let fill = if i % 2 == 0 { '#' } else { '.' };
        let mut s = String::from("\x1b[2J\x1b[H");
        for r in 1..=ROWS {
            s.push_str(&format!(
                "\x1b[{r};1H{}",
                fill.to_string().repeat(COLS as usize)
            ));
        }
        s.into_bytes()
    });
    bench("full repaint (whole screen/frame)", &heavy, 200);
}
