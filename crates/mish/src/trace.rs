//! Optional structured event logging for debugging (and, later, analytics and
//! session replay).
//!
//! When a binary is started with `--log-file PATH`, [`init_file_logging`]
//! installs a JSON-lines [`tracing`] subscriber that writes every significant
//! session event to that file: connection lifecycle, the PTY child exiting, the
//! SSP shutdown handshake, and driver start/stop. Lining up a client log against
//! a server log makes issues like "the session won't disconnect" obvious — you
//! can see exactly which side stopped talking and why.
//!
//! ## Why this shape
//!
//! * **`tracing` as the event bus.** Instrumentation lives at the call sites as
//!   ordinary `tracing` events; when no subscriber is installed they compile down
//!   to a cheap disabled-level check, so an un-logged session pays ~nothing. The
//!   same events can later feed a perf-analytics layer or a capture sink without
//!   touching the call sites.
//! * **JSON lines.** Greppable by eye, parseable by tools — the substrate the
//!   future analytics/replay features will consume.
//! * **Synchronous `Mutex<File>` writer (not `tracing-appender`).** The server
//!   `fork()`s to daemonize; a background-thread writer would not survive the
//!   fork. A plain locked file does, and the logging volume here is tiny.
//! * **`uptime` timestamps + a wall-clock anchor.** Each line is stamped with
//!   seconds since the log opened (monotonic, ideal for spotting stalls); the
//!   one-time `init` event also records `unix_ms` so a client and server log can
//!   be aligned on the wall clock.
//!
//! This is the first slice of a broader capture story (packet capture, perf
//! analytics, deterministic replay); those build on the same structured events.

use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use tracing::Level;
use tracing_subscriber::fmt::time::uptime;

/// Install a JSON event-log subscriber writing to `path` (created if absent,
/// appended otherwise). `role` ("client" / "server") and the process id are
/// recorded in the opening event so a merged or mislabeled log is still
/// unambiguous. `level` is the maximum verbosity captured.
///
/// Call once, early, and — on the server — **before** the daemonize `fork()`: the
/// open file descriptor and the global subscriber are inherited by the child, and
/// the writer spawns no threads, so logging keeps working across the fork.
///
/// Returns the file-open error if `path` can't be created/opened. Calling this
/// more than once (or alongside another global subscriber) leaves the first
/// subscriber in place; the redundant call is reported via the returned error
/// from `try_init` being swallowed — callers init at most once.
pub fn init_file_logging(path: &Path, role: &'static str, level: Level) -> std::io::Result<()> {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;

    // `try_init` (not `init`) so a second call — or a process that already has a
    // subscriber — doesn't panic; the first subscriber wins.
    let installed = tracing_subscriber::fmt()
        .json()
        .with_timer(uptime())
        .with_max_level(level)
        .with_target(true)
        .with_writer(Mutex::new(file))
        .try_init()
        .is_ok();

    if installed {
        let unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        tracing::info!(
            role,
            pid = std::process::id(),
            unix_ms = unix_ms as u64,
            version = env!("CARGO_PKG_VERSION"),
            "event log initialized"
        );
    }
    Ok(())
}

/// Parse a log-level string (`error|warn|info|debug|trace`, case-insensitive).
/// Falls back to `Level::DEBUG` for anything unrecognized so a typo still yields
/// a useful log rather than a hard failure.
pub fn parse_level(s: &str) -> Level {
    match s.to_ascii_lowercase().as_str() {
        "error" => Level::ERROR,
        "warn" => Level::WARN,
        "info" => Level::INFO,
        "trace" => Level::TRACE,
        _ => Level::DEBUG,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_level_is_case_insensitive_and_defaults_to_debug() {
        assert_eq!(parse_level("ERROR"), Level::ERROR);
        assert_eq!(parse_level("Warn"), Level::WARN);
        assert_eq!(parse_level("info"), Level::INFO);
        assert_eq!(parse_level("trace"), Level::TRACE);
        assert_eq!(parse_level("debug"), Level::DEBUG);
        // Unrecognized → debug (a typo still yields a useful log).
        assert_eq!(parse_level("verbose"), Level::DEBUG);
        assert_eq!(parse_level(""), Level::DEBUG);
    }
}
