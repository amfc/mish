//! Optional per-keystroke latency recording for `mish-client` (`--perf-log`).
//!
//! When the client is started with `--perf-log PATH`, [`init`] installs a
//! process-global recorder that writes one JSON line per keystroke measuring its
//! **keypress → on-screen display** latency — the metric from the Mosh paper's
//! response-time graph (Winstein & Balakrishnan, USENIX ATC 2012). The point is
//! to capture this from a *real* interactive session (e.g. over SSH to a remote
//! host) and then plot the distribution; see `perf/`.
//!
//! ## What is measured
//!
//! For each keystroke (one `ClientInput::Keys` batch), all stamped from the one
//! monotonic client clock ([`mish_ssp::clock::SystemClock`]):
//!
//! * `press_ms`   — the keystroke bytes arrived;
//! * `display_ms` — the key first became visible on the painted frame: equal to
//!   `press_ms` when predictive local echo showed it immediately, otherwise the
//!   moment the server's real screen confirmed it (`echo_ack >= idx`);
//! * `confirm_ms` — the server confirmed the key (true round-trip), or `null` if
//!   the session ended first.
//!
//! `response_ms = display_ms − press_ms` is the paper's "response time": ~0 for a
//! predicted key, ~RTT for an unpredicted one.
//!
//! ## Why this shape
//!
//! Like [`crate::trace`]'s `--log-file`, the recorder is a **global** installed in
//! `main`, so it stays out of [`crate::client::run_client`]'s signature (and its
//! many headless test call sites). The hooks short-circuit on a relaxed
//! [`AtomicBool`] when the flag is off, so an un-instrumented session pays ~nothing.
//! A synchronous `Mutex<BufWriter<File>>` (not a background thread) is used and
//! **flushed eagerly**, because the client exits via `process::exit` (see
//! `mish-client::exit_now`), which runs no destructors — a buffered-but-unflushed
//! tail would be lost. Records are tiny and only emitted at keystroke/ack rate, so
//! the locking and flushing cost is negligible.
//!
//! The bookkeeping ([`PerfState`]) is split out as pure, I/O-free logic so it can
//! be unit-tested without touching the global or the filesystem.

use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

/// One finalized keystroke-latency measurement, written as a single JSON line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PerfRecord {
    /// Client input index (`UserStream::total()`) this keystroke landed at.
    pub idx: u64,
    /// Monotonic ms the keystroke bytes were received.
    pub press_ms: u64,
    /// Monotonic ms the keystroke first became visible — equal to `press_ms` when
    /// a local prediction echoed it, else the server-confirmation time.
    pub display_ms: u64,
    /// Monotonic ms the server confirmed it (`echo_ack >= idx`), or `None` if the
    /// session ended before it was acknowledged.
    pub confirm_ms: Option<u64>,
    /// Whether predictive local echo displayed it (so `display_ms == press_ms`)
    /// rather than waiting for the server round-trip.
    pub predicted: bool,
    /// Number of input bytes in the keystroke batch (≈1 for normal typing).
    pub nbytes: usize,
}

impl PerfRecord {
    /// Keypress → on-screen display latency (ms): the paper's "response time".
    pub fn response_ms(&self) -> u64 {
        self.display_ms - self.press_ms
    }

    /// Server round-trip latency (ms), if the key was confirmed before the
    /// session ended.
    pub fn confirm_latency_ms(&self) -> Option<u64> {
        self.confirm_ms.map(|c| c - self.press_ms)
    }

    /// Serialize as one JSON object line. Written by hand (no `serde_json`
    /// dependency): every field is a number or bool, so no string escaping is
    /// needed and the output is a stable, greppable contract for the grapher.
    fn write_json(&self, w: &mut impl Write) -> std::io::Result<()> {
        let confirm = match self.confirm_ms {
            Some(c) => c.to_string(),
            None => "null".to_string(),
        };
        writeln!(
            w,
            "{{\"idx\":{},\"press_ms\":{},\"display_ms\":{},\"confirm_ms\":{},\"predicted\":{},\"nbytes\":{}}}",
            self.idx, self.press_ms, self.display_ms, confirm, self.predicted, self.nbytes
        )
    }
}

/// A keystroke awaiting server confirmation.
#[derive(Clone, Copy)]
struct Pending {
    idx: u64,
    press_ms: u64,
    nbytes: usize,
    /// Set once the key has been displayed (by local prediction) before it was
    /// confirmed; `None` until then.
    display_ms: Option<u64>,
    predicted: bool,
}

/// Pure keystroke-latency bookkeeping (no I/O), unit-testable in isolation.
///
/// Keystrokes are pushed in input order and finalized — into [`PerfRecord`]s — as
/// the server acknowledges them. Both `on_keystroke` and `on_ack`/`flush_unacked`
/// are called from `run_client`'s single task, so no internal locking is needed
/// (the global wrapper provides the `Mutex`).
#[derive(Default)]
pub struct PerfState {
    pending: Vec<Pending>,
}

impl PerfState {
    pub fn new() -> Self {
        Self {
            pending: Vec::new(),
        }
    }

    /// Record a keystroke typed at input index `idx` (its `UserStream::total()`),
    /// received at `press_ms`. `shown_now` is whether predictive local echo is
    /// already displaying it — if so its display latency is ~0 (`display_ms ==
    /// press_ms`); otherwise the key is held pending until the server confirms it.
    pub fn on_keystroke(&mut self, idx: u64, press_ms: u64, shown_now: bool, nbytes: usize) {
        self.pending.push(Pending {
            idx,
            press_ms,
            nbytes,
            display_ms: shown_now.then_some(press_ms),
            predicted: shown_now,
        });
    }

    /// The server has confirmed everything with `idx <= echo_ack`, as of
    /// `now_ms`. Finalize those keystrokes — a not-yet-displayed one first paints
    /// now (its glyph round-tripped) — and return the records in input order.
    pub fn on_ack(&mut self, echo_ack: u64, now_ms: u64) -> Vec<PerfRecord> {
        let mut done = Vec::new();
        let mut i = 0;
        while i < self.pending.len() {
            if self.pending[i].idx <= echo_ack {
                let p = self.pending.remove(i);
                done.push(PerfRecord {
                    idx: p.idx,
                    press_ms: p.press_ms,
                    // Predicted keys keep their (earlier) local display time; an
                    // unpredicted key first shows now, on confirmation.
                    display_ms: p.display_ms.unwrap_or(now_ms),
                    confirm_ms: Some(now_ms),
                    predicted: p.predicted,
                    nbytes: p.nbytes,
                });
            } else {
                i += 1;
            }
        }
        done
    }

    /// Session ending: emit keystrokes that were displayed but never confirmed
    /// (`confirm_ms = None`). An *undisplayed* unacked key is dropped — it never
    /// reached the screen, so it has no response-time sample to report.
    pub fn flush_unacked(&mut self) -> Vec<PerfRecord> {
        let mut done = Vec::new();
        for p in self.pending.drain(..) {
            if let Some(display_ms) = p.display_ms {
                done.push(PerfRecord {
                    idx: p.idx,
                    press_ms: p.press_ms,
                    display_ms,
                    confirm_ms: None,
                    predicted: p.predicted,
                    nbytes: p.nbytes,
                });
            }
        }
        done
    }
}

// ---------------------------------------------------------------------------
// Process-global recorder (the `--perf-log` sink)
// ---------------------------------------------------------------------------

struct Recorder {
    state: PerfState,
    writer: BufWriter<std::fs::File>,
}

static RECORDER: OnceLock<Mutex<Recorder>> = OnceLock::new();
static ENABLED: AtomicBool = AtomicBool::new(false);

/// Install the global recorder, writing JSON lines to `path` (created, or
/// truncated if it exists). Enables the `on_*` hooks. The first call wins; a
/// redundant second call is ignored. Returns the file-open error if any.
pub fn init(path: &Path) -> std::io::Result<()> {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)?;
    let recorder = Recorder {
        state: PerfState::new(),
        writer: BufWriter::new(file),
    };
    // First init wins; a redundant second call leaves the original in place.
    if RECORDER.set(Mutex::new(recorder)).is_ok() {
        ENABLED.store(true, Ordering::Relaxed);
    }
    Ok(())
}

/// Whether perf recording is active. Cheap relaxed load so the hooks below
/// short-circuit to nothing when `--perf-log` was not given.
#[inline]
pub fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

/// Record a keystroke at input index `idx` (received at `press_ms`), with
/// `shown_now` = whether predictive echo is already displaying it. No-op unless
/// recording is enabled.
pub fn on_keystroke(idx: u64, press_ms: u64, shown_now: bool, nbytes: usize) {
    if !enabled() {
        return;
    }
    if let Some(m) = RECORDER.get() {
        m.lock()
            .unwrap()
            .state
            .on_keystroke(idx, press_ms, shown_now, nbytes);
    }
}

/// Note a server confirmation up to `echo_ack` at `now_ms`, writing out every
/// keystroke it finalizes. Flushed eagerly (the client exits via `process::exit`,
/// which won't run the writer's destructor). No-op unless enabled.
pub fn on_ack(echo_ack: u64, now_ms: u64) {
    if !enabled() {
        return;
    }
    if let Some(m) = RECORDER.get() {
        let mut r = m.lock().unwrap();
        let records = r.state.on_ack(echo_ack, now_ms);
        if records.is_empty() {
            return;
        }
        for rec in records {
            let _ = rec.write_json(&mut r.writer);
        }
        let _ = r.writer.flush();
    }
}

/// Flush any displayed-but-unconfirmed keystrokes and the writer. Safe to call
/// more than once (a second call finds nothing pending). No-op unless enabled.
pub fn finish() {
    if !enabled() {
        return;
    }
    if let Some(m) = RECORDER.get() {
        let mut r = m.lock().unwrap();
        let records = r.state.flush_unacked();
        for rec in records {
            let _ = rec.write_json(&mut r.writer);
        }
        let _ = r.writer.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn predicted_key_has_zero_response() {
        let mut s = PerfState::new();
        // Shown locally the instant it was typed.
        s.on_keystroke(1, 100, true, 1);
        let recs = s.on_ack(1, 175); // server confirms 75 ms later
        assert_eq!(recs.len(), 1);
        let r = recs[0];
        assert!(r.predicted);
        assert_eq!(r.display_ms, 100, "predicted key displays at press time");
        assert_eq!(r.response_ms(), 0);
        assert_eq!(r.confirm_ms, Some(175));
        assert_eq!(r.confirm_latency_ms(), Some(75));
    }

    #[test]
    fn unpredicted_key_response_is_the_round_trip() {
        let mut s = PerfState::new();
        s.on_keystroke(2, 200, false, 1); // not echoed locally
        let recs = s.on_ack(2, 280);
        assert_eq!(recs.len(), 1);
        let r = recs[0];
        assert!(!r.predicted);
        assert_eq!(r.display_ms, 280, "unpredicted key first shows on confirm");
        assert_eq!(r.response_ms(), 80);
    }

    #[test]
    fn ack_only_finalizes_up_to_echo_ack() {
        let mut s = PerfState::new();
        s.on_keystroke(5, 500, true, 1);
        s.on_keystroke(6, 510, true, 1);
        // A resize bumps the index between keystrokes — echo_ack of 5 confirms
        // only the first keystroke.
        let recs = s.on_ack(5, 560);
        assert_eq!(recs.iter().map(|r| r.idx).collect::<Vec<_>>(), vec![5]);
        // The next ack confirms the rest, in order.
        let recs = s.on_ack(6, 600);
        assert_eq!(recs.iter().map(|r| r.idx).collect::<Vec<_>>(), vec![6]);
    }

    #[test]
    fn flush_keeps_displayed_drops_undisplayed() {
        let mut s = PerfState::new();
        s.on_keystroke(3, 300, true, 1); // displayed (predicted) but never acked
        s.on_keystroke(4, 400, false, 1); // never displayed and never acked
        let recs = s.flush_unacked();
        assert_eq!(recs.len(), 1, "only the displayed key has a sample");
        assert_eq!(recs[0].idx, 3);
        assert_eq!(recs[0].confirm_ms, None);
        assert_eq!(recs[0].response_ms(), 0);
        // Draining leaves nothing for a second flush.
        assert!(s.flush_unacked().is_empty());
    }

    #[test]
    fn json_line_is_the_expected_contract() {
        let mut buf = Vec::new();
        PerfRecord {
            idx: 7,
            press_ms: 1000,
            display_ms: 1000,
            confirm_ms: Some(1080),
            predicted: true,
            nbytes: 1,
        }
        .write_json(&mut buf)
        .unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "{\"idx\":7,\"press_ms\":1000,\"display_ms\":1000,\"confirm_ms\":1080,\"predicted\":true,\"nbytes\":1}\n"
        );

        // An unconfirmed record serializes `confirm_ms` as JSON null.
        let mut buf = Vec::new();
        PerfRecord {
            idx: 8,
            press_ms: 2000,
            display_ms: 2000,
            confirm_ms: None,
            predicted: true,
            nbytes: 2,
        }
        .write_json(&mut buf)
        .unwrap();
        assert!(String::from_utf8(buf)
            .unwrap()
            .contains("\"confirm_ms\":null"));
    }
}
