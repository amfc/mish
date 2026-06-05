//! Controlled server-side child for the latency harness. It continuously repaints
//! a marker carrying the current wall-clock time (CLOCK_REALTIME nanoseconds) at a
//! fixed screen position. The harness reads the marker off the *client's*
//! reconstructed screen and subtracts to get the one-way display latency — the
//! two processes share the machine clock, so the difference is the real delay
//! from server emit to client display.
//!
//! Runs as a single argv[0] program (no shell), so both `mish-server -- <this>`
//! and `mosh-server new -- <this>` can launch it.

use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    let mut out = std::io::stdout().lock();
    loop {
        let ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        // Cursor to row 10, col 1; print the marker (trailing spaces clear stale
        // digits when the number shrinks). Row 10 avoids the client's row-0 status
        // banner.
        let _ = write!(out, "\x1b[10;1H[TS {ns}]        ");
        let _ = out.flush();
        std::thread::sleep(std::time::Duration::from_millis(30));
    }
}
