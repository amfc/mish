//! Status-bar overlay (the client's `Ctrl-^ u` toggle).
//!
//! A reverse-video banner on the top row showing live link and prediction health
//! — session name, smoothed RTT, recent packet loss, recent prediction accuracy
//! and state, and the current peer address (which changes when QUIC roams). Like
//! [`crate::notification`]'s stall banner, it is overlaid on the displayed screen
//! just before painting and occupies the top row; toggling it off (or any normal
//! repaint) restores the real top row. The two never co-exist: the client shows
//! the stall banner when the link is silent and this bar otherwise.

use crate::predict::PredictMode;
use crate::screen::{Cell, Color, Screen, F_INVERSE, NAMED_BACKGROUND, NAMED_FOREGROUND};

/// Live link/prediction metrics for the status bar, gathered by the client each
/// repaint. Display-only. Fields are `Option` where the datum may be unavailable
/// (an unnamed session, a transport that reports no loss counters, no predictions
/// confirmed yet in the window).
#[derive(Clone, Debug)]
pub struct LinkStats {
    /// Named session (`--session NAME`), or `None` for an unnamed session.
    pub session: Option<String>,
    /// Smoothed round-trip-time estimate (ms); `<= 0` ⇒ not yet measured.
    pub rtt_ms: f64,
    /// Recent packet-loss fraction (`0.0..=1.0`), or `None` if the transport
    /// reports no loss counters or the sampling window is still empty.
    pub loss: Option<f64>,
    /// Recent prediction accuracy as `(sample_count, fraction_correct)`, or `None`
    /// if no predictions were confirmed in the window.
    pub prediction: Option<(u32, f64)>,
    /// Whether the prediction overlay is currently displaying to the user.
    pub predicting: bool,
    /// Whether predictions are currently flagged glitchy (pending long enough to
    /// look stalled).
    pub glitchy: bool,
    /// The configured prediction mode.
    pub predict_mode: PredictMode,
    /// Current peer address (changes on QUIC roaming), or `None`.
    pub peer: Option<String>,
    /// Seconds since the last datagram from the server.
    pub silent_secs: u64,
}

impl Default for LinkStats {
    fn default() -> Self {
        Self {
            session: None,
            rtt_ms: 0.0,
            loss: None,
            prediction: None,
            predicting: false,
            glitchy: false,
            predict_mode: PredictMode::Adaptive,
            peer: None,
            silent_secs: 0,
        }
    }
}

/// One-word summary of the prediction state for the bar.
fn predict_word(s: &LinkStats) -> &'static str {
    match s.predict_mode {
        PredictMode::Never => "off",
        _ if s.glitchy => "glitch",
        _ if s.predicting => "on",
        _ => "idle",
    }
}

/// The full status line for `stats` (untruncated; the renderer clips to width).
pub fn status_text(s: &LinkStats) -> String {
    let mut segs: Vec<String> = Vec::with_capacity(6);
    segs.push("mish".to_string());
    if let Some(name) = &s.session {
        segs.push(name.clone());
    }
    segs.push(if s.rtt_ms > 0.0 {
        format!("rtt {:.0}ms", s.rtt_ms)
    } else {
        "rtt —".to_string()
    });
    segs.push(match s.loss {
        Some(f) => format!("loss {:.1}%", f * 100.0),
        None => "loss —".to_string(),
    });
    segs.push(match s.prediction {
        Some((_, acc)) => format!("pred {:.0}% {}", acc * 100.0, predict_word(s)),
        None => format!("pred — {}", predict_word(s)),
    });
    if s.silent_secs >= 2 {
        segs.push(format!("silent {}s", s.silent_secs));
    }
    if let Some(peer) = &s.peer {
        segs.push(peer.clone());
    }
    segs.join(" · ")
}

/// Return a copy of `screen` with the status bar on its top row (reverse video),
/// or `None` for an empty screen (no row to write on — nothing received yet).
pub fn status_bar_overlay(screen: &Screen, stats: &LinkStats) -> Option<Screen> {
    if screen.rows == 0 || screen.cols == 0 {
        return None;
    }
    let mut s = screen.clone();
    write_bar(&mut s, &status_text(stats));
    Some(s)
}

/// Write `text` across the top row in reverse video, padded to the full width.
/// (Same shape as [`crate::notification`]'s banner; kept separate so the two
/// overlays can evolve independently.)
fn write_bar(s: &mut Screen, text: &str) {
    let cols = s.cols as usize;
    let chars: Vec<char> = text.chars().collect();
    for (col, cell) in s.cells[..cols].iter_mut().enumerate() {
        *cell = Cell {
            c: chars.get(col).copied().unwrap_or(' '),
            fg: Color::Named(NAMED_FOREGROUND),
            bg: Color::Named(NAMED_BACKGROUND),
            flags: F_INVERSE,
            combining: Vec::new(),
            hyperlink: None,
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> LinkStats {
        LinkStats {
            session: Some("work".into()),
            rtt_ms: 42.0,
            loss: Some(0.012),
            prediction: Some((30, 0.97)),
            predicting: true,
            glitchy: false,
            predict_mode: PredictMode::Adaptive,
            peer: Some("1.2.3.4:60001".into()),
            silent_secs: 0,
        }
    }

    #[test]
    fn text_includes_all_segments() {
        let t = status_text(&sample());
        assert!(t.contains("work"), "{t}");
        assert!(t.contains("rtt 42ms"), "{t}");
        assert!(t.contains("loss 1.2%"), "{t}");
        assert!(t.contains("pred 97% on"), "{t}");
        assert!(t.contains("1.2.3.4:60001"), "{t}");
    }

    #[test]
    fn missing_data_renders_dashes() {
        let s = LinkStats {
            rtt_ms: 0.0,
            loss: None,
            prediction: None,
            ..LinkStats::default()
        };
        let t = status_text(&s);
        assert!(t.contains("rtt —"), "{t}");
        assert!(t.contains("loss —"), "{t}");
        assert!(t.contains("pred — idle"), "{t}");
    }

    #[test]
    fn predict_word_reflects_state() {
        let mut s = sample();
        s.predict_mode = PredictMode::Never;
        assert_eq!(predict_word(&s), "off");
        s.predict_mode = PredictMode::Adaptive;
        s.glitchy = true;
        assert_eq!(predict_word(&s), "glitch");
        s.glitchy = false;
        s.predicting = false;
        assert_eq!(predict_word(&s), "idle");
    }

    #[test]
    fn silent_segment_only_when_stale() {
        let mut s = sample();
        assert!(!status_text(&s).contains("silent"));
        s.silent_secs = 2;
        assert!(status_text(&s).contains("silent 2s"));
    }

    #[test]
    fn bar_is_reverse_video_full_width() {
        let screen = Screen::blank(80, 5);
        let over = status_bar_overlay(&screen, &sample()).expect("non-empty → overlay");
        let row: String = (0..80).map(|c| over.cell(0, c).unwrap().c).collect();
        assert!(row.starts_with("mish · work · rtt 42ms"), "{row}");
        for c in 0..80 {
            assert_ne!(
                over.cell(0, c).unwrap().flags & F_INVERSE,
                0,
                "col {c} not reverse"
            );
        }
        // Rows below are untouched.
        assert_eq!(over.cells[80..], screen.cells[80..]);
    }

    #[test]
    fn narrow_screen_truncates_without_panic() {
        let screen = Screen::blank(8, 2);
        let over = status_bar_overlay(&screen, &sample()).unwrap();
        let row: String = (0..8).map(|c| over.cell(0, c).unwrap().c).collect();
        assert_eq!(row, "mish · w");
    }

    #[test]
    fn empty_screen_no_panic() {
        use mish_ssp::state::SyncState;
        assert!(status_bar_overlay(&Screen::new_initial(), &sample()).is_none());
    }
}
