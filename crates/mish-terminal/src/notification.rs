//! Connection-status overlay — a small port of mosh's `NotificationEngine`.
//!
//! When the link stalls (no datagram from the server for a few seconds) the user
//! otherwise gets no feedback at all. This renders a reverse-video banner on the
//! top row — "mish: Last contact N seconds ago. [To quit, press Ctrl-^ .]" — so a
//! frozen session is legible. The banner is overlaid on the displayed screen just
//! before painting; once contact resumes, the next normal repaint restores the
//! real top row.

use crate::screen::{Cell, Color, Screen, F_INVERSE, NAMED_BACKGROUND, NAMED_FOREGROUND};

/// Seconds without contact before the stall banner appears.
pub const STALE_SECS: u64 = 3;

/// The banner text for a link silent for `secs` seconds.
pub fn status_text(secs: u64) -> String {
    format!(
        "mish: Last contact {secs} {} ago. [To quit, press Ctrl-^ then .]",
        if secs == 1 { "second" } else { "seconds" }
    )
}

/// If the link has been silent for at least [`STALE_SECS`], return a copy of
/// `screen` with the stall banner on its top row (reverse video); otherwise
/// `None` (caller paints the screen unchanged). Returns `None` for an empty
/// screen (nothing received yet — no row to write on).
pub fn stalled_overlay(screen: &Screen, secs_since_contact: u64) -> Option<Screen> {
    if secs_since_contact < STALE_SECS || screen.rows == 0 || screen.cols == 0 {
        return None;
    }
    let mut s = screen.clone();
    write_banner(&mut s, &status_text(secs_since_contact));
    Some(s)
}

/// Write `text` across the top row in reverse video, padded to the full width.
fn write_banner(s: &mut Screen, text: &str) {
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

    #[test]
    fn no_overlay_when_fresh() {
        let s = Screen::blank(40, 5);
        assert!(stalled_overlay(&s, 0).is_none());
        assert!(stalled_overlay(&s, STALE_SECS - 1).is_none());
    }

    #[test]
    fn overlay_appears_when_stale() {
        let s = Screen::blank(80, 5);
        let over = stalled_overlay(&s, 7).expect("stale → overlay");
        // Top row carries the (reverse-video) banner text.
        let row: String = (0..80).map(|c| over.cell(0, c).unwrap().c).collect();
        assert!(row.starts_with("mish: Last contact 7 seconds ago."));
        assert!(row.contains("Ctrl-^"));
        for c in 0..80 {
            assert_ne!(
                over.cell(0, c).unwrap().flags & F_INVERSE,
                0,
                "banner row is reverse-video across the full width"
            );
        }
        // Rows below are untouched.
        assert_eq!(over.cells[80..], s.cells[80..]);
    }

    #[test]
    fn banner_truncates_to_width() {
        let s = Screen::blank(10, 2); // narrower than the text
        let over = stalled_overlay(&s, 5).unwrap();
        // Exactly `cols` cells written, no panic/overflow.
        let row: String = (0..10).map(|c| over.cell(0, c).unwrap().c).collect();
        assert_eq!(row, "mish: Last");
    }

    #[test]
    fn singular_second() {
        assert!(status_text(1).contains("1 second "));
        assert!(status_text(2).contains("2 seconds "));
    }

    #[test]
    fn empty_screen_no_panic() {
        use mish_ssp::state::SyncState;
        assert!(stalled_overlay(&Screen::new_initial(), 99).is_none());
    }
}
