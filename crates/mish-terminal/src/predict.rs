//! Client-side predictive echo — speculative local display of keystrokes before
//! the server confirms them, modeled on mosh's `terminaloverlay` PredictionEngine.
//!
//! On a high-latency link, echoing each keystroke only after a server round-trip
//! feels sluggish. The prediction engine overlays the *likely* result of local
//! input onto the displayed screen immediately, then validates each prediction
//! when the server's real screen catches up (tracked via [`Screen::echo_ack`],
//! the count of client input events the server has applied). Correct predictions
//! quietly disappear into the real screen; an incorrect one flushes the
//! speculation and the true screen is shown.
//!
//! Correctness focus (mosh's `prediction-unicode` regression): keystroke bytes
//! are decoded as **complete UTF-8 scalar values** before any glyph is
//! predicted, so a multi-byte character is never split into a corrupt
//! prediction.

use crate::screen::{Cell, Screen};

/// When to show predictions.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PredictMode {
    /// Never predict; always show exactly what the server sent.
    Never,
    /// Always overlay predictions (mosh's `--predict=always`).
    Always,
    /// Overlay predictions only when the link is laggy enough to benefit
    /// (mosh's default `--predict=adaptive`), gated on the SRTT estimate.
    Adaptive,
}

/// SRTT (ms) at or above which adaptive prediction switches on. Mirrors mosh's
/// notion that prediction helps once the round-trip is perceptible.
const ADAPTIVE_SRTT_TRIGGER_MS: f64 = 50.0;

#[derive(Clone)]
struct CellPrediction {
    row: u16,
    col: u16,
    cell: Cell,
    /// Client input index (`UserStream::total()`) at which this was predicted.
    input_index: u64,
}

/// Speculative overlay of unconfirmed local input.
pub struct PredictionEngine {
    mode: PredictMode,
    cells: Vec<CellPrediction>,
    cursor_row: u16,
    cursor_col: u16,
    cursor_index: u64,
    have_cursor: bool,
    /// Buffer for an incomplete trailing UTF-8 sequence.
    utf8: Vec<u8>,
    /// Once an unpredictable byte (escape/control) is seen, suppress prediction
    /// for the rest of the current input batch (the escape sequence's remaining
    /// bytes must not be echoed as text).
    suppress: bool,
    /// Latest SRTT estimate (ms), for adaptive gating.
    srtt_ms: f64,
    /// Underline tentative (unconfirmed) predictions so they read as speculative
    /// (mosh's prediction "flagging").
    flagging: bool,
    /// After a misprediction, briefly suppress the overlay until the next clean
    /// server update, to avoid flicker (mosh's glitch trigger).
    glitch: bool,
    cols: u16,
    rows: u16,
}

impl PredictionEngine {
    pub fn new(mode: PredictMode) -> Self {
        Self {
            mode,
            cells: Vec::new(),
            cursor_row: 0,
            cursor_col: 0,
            cursor_index: 0,
            have_cursor: false,
            utf8: Vec::new(),
            suppress: false,
            srtt_ms: 0.0,
            flagging: true,
            glitch: false,
            cols: 0,
            rows: 0,
        }
    }

    /// Update the SRTT estimate used by [`PredictMode::Adaptive`] gating.
    pub fn set_srtt(&mut self, srtt_ms: f64) {
        self.srtt_ms = srtt_ms;
    }

    /// Toggle underlining of tentative predictions (default on).
    pub fn set_flagging(&mut self, on: bool) {
        self.flagging = on;
    }

    /// Whether predictions should currently be displayed.
    fn showing(&self) -> bool {
        if self.glitch {
            return false; // suppressed after a recent misprediction
        }
        match self.mode {
            PredictMode::Never => false,
            PredictMode::Always => true,
            PredictMode::Adaptive => self.srtt_ms >= ADAPTIVE_SRTT_TRIGGER_MS,
        }
    }

    fn reset(&mut self) {
        self.cells.clear();
        self.have_cursor = false;
        self.utf8.clear();
    }

    /// Register local keystroke `bytes`, typed at client input index
    /// `input_index` (the `UserStream::total()` after appending them), against
    /// the currently displayed `base` screen.
    pub fn new_user_bytes(&mut self, bytes: &[u8], base: &Screen, input_index: u64) {
        if self.mode == PredictMode::Never {
            return;
        }
        self.cols = base.cols;
        self.rows = base.rows;
        if self.cols == 0 || self.rows == 0 {
            return;
        }
        if !self.have_cursor {
            self.cursor_row = base.cursor_row.min(self.rows - 1);
            self.cursor_col = base.cursor_col.min(self.cols - 1);
            self.have_cursor = true;
        }
        // Each batch starts predictable again.
        self.suppress = false;

        self.utf8.extend_from_slice(bytes);
        // Decode and predict only complete scalar values; keep an incomplete
        // trailing sequence buffered for the next batch.
        loop {
            match std::str::from_utf8(&self.utf8) {
                Ok(s) => {
                    let chars: Vec<char> = s.chars().collect();
                    self.utf8.clear();
                    for ch in chars {
                        self.predict_char(ch, input_index);
                    }
                    break;
                }
                Err(e) => {
                    let valid = e.valid_up_to();
                    if valid > 0 {
                        let chars: Vec<char> = std::str::from_utf8(&self.utf8[..valid])
                            .unwrap()
                            .chars()
                            .collect();
                        for ch in chars {
                            self.predict_char(ch, input_index);
                        }
                    }
                    match e.error_len() {
                        // Incomplete trailing sequence: keep it for next time.
                        None => {
                            self.utf8.drain(..valid);
                            break;
                        }
                        // Invalid byte(s): drop them (don't predict garbage) and
                        // continue with whatever follows.
                        Some(bad) => {
                            self.utf8.drain(..valid + bad);
                        }
                    }
                }
            }
        }
    }

    fn predict_char(&mut self, ch: char, input_index: u64) {
        if self.suppress {
            return; // inside an unpredictable (escape) sequence
        }
        match ch {
            // Carriage return: go to column 0.
            '\r' => {
                self.cursor_col = 0;
                self.cursor_index = input_index;
            }
            // Line feed: next row (predicting scroll is unsafe, so clamp).
            '\n' => {
                self.cursor_col = 0;
                if self.cursor_row + 1 < self.rows {
                    self.cursor_row += 1;
                }
                self.cursor_index = input_index;
            }
            // Backspace / delete: move left and predict an erased cell.
            '\u{8}' | '\u{7f}' => {
                self.cursor_col = self.cursor_col.saturating_sub(1);
                let cell = Cell {
                    c: ' ',
                    ..Cell::default()
                };
                self.push_cell(cell, input_index);
                self.cursor_index = input_index;
            }
            // Tab: advance to the next multiple of 8.
            '\t' => {
                let next = ((self.cursor_col / 8) + 1) * 8;
                self.cursor_col = next.min(self.cols - 1);
                self.cursor_index = input_index;
            }
            // Any other control character or escape: we can't safely predict the
            // effect, so abandon speculation and fall back to the real screen.
            c if (c as u32) < 0x20 || c == '\u{1b}' => {
                self.reset();
                self.suppress = true;
            }
            // Printable: echo the glyph and advance by its display width.
            c => {
                use unicode_width::UnicodeWidthChar;
                match UnicodeWidthChar::width(c).unwrap_or(1) {
                    0 => {
                        // Combining mark: attach to the cell just to our left.
                        let (r, pc) = (self.cursor_row, self.cursor_col.saturating_sub(1));
                        if let Some(p) = self.cells.iter_mut().find(|p| p.row == r && p.col == pc) {
                            p.cell.combining.push(c);
                        }
                    }
                    2 => {
                        // Wide char: the glyph cell plus a blank spacer (width is
                        // derived from the char, so no flags are needed).
                        let wide = Cell {
                            c,
                            ..Cell::default()
                        };
                        self.push_cell(wide, input_index);
                        self.advance_cursor();
                        let spacer = Cell {
                            c: ' ',
                            ..Cell::default()
                        };
                        self.push_cell(spacer, input_index);
                        self.advance_cursor();
                    }
                    _ => {
                        let cell = Cell {
                            c,
                            ..Cell::default()
                        };
                        self.push_cell(cell, input_index);
                        self.advance_cursor();
                    }
                }
                self.cursor_index = input_index;
            }
        }
    }

    fn push_cell(&mut self, cell: Cell, input_index: u64) {
        let (row, col) = (self.cursor_row, self.cursor_col);
        // Replace any existing prediction at this position.
        self.cells.retain(|p| !(p.row == row && p.col == col));
        self.cells.push(CellPrediction {
            row,
            col,
            cell,
            input_index,
        });
    }

    fn advance_cursor(&mut self) {
        if self.cursor_col + 1 < self.cols {
            self.cursor_col += 1;
        } else {
            // Wrap.
            self.cursor_col = 0;
            if self.cursor_row + 1 < self.rows {
                self.cursor_row += 1;
            }
        }
    }

    /// Incorporate a freshly received server screen: validate predictions the
    /// server has now applied (`input_index <= screen.echo_ack`) and cull or, on
    /// a misprediction, flush everything.
    pub fn new_server_screen(&mut self, screen: &Screen) {
        if self.mode == PredictMode::Never {
            self.reset();
            return;
        }
        let ack = screen.echo_ack;

        // A mispredicted, now-confirmed cell means our speculation diverged from
        // reality: drop all predictions and resync to the server.
        let mispredict = self.cells.iter().any(|p| {
            p.input_index <= ack
                && screen
                    .cell(p.row, p.col)
                    .map(|actual| actual.c != p.cell.c)
                    .unwrap_or(true)
        });
        if mispredict {
            self.reset();
            self.glitch = true; // suppress overlay until the next clean update
            return;
        }

        // A clean update clears any glitch suppression.
        self.glitch = false;

        // Drop confirmed-correct predictions (the real screen now shows them).
        self.cells.retain(|p| p.input_index > ack);
        if self.cursor_index <= ack {
            self.have_cursor = false;
        }
    }

    /// The screen to display: the server screen with active predictions overlaid.
    pub fn predicted_screen(&self, server: &Screen) -> Screen {
        if !self.showing() || (self.cells.is_empty() && !self.have_cursor) {
            return server.clone();
        }
        let mut s = server.clone();
        for p in &self.cells {
            if p.input_index > server.echo_ack {
                if let (true, true) = (p.row < s.rows, p.col < s.cols) {
                    let idx = p.row as usize * s.cols as usize + p.col as usize;
                    let mut cell = p.cell.clone();
                    // Underline tentative predictions so they read as speculative.
                    if self.flagging {
                        cell.flags |= crate::screen::F_UNDERLINE;
                    }
                    s.cells[idx] = cell;
                }
            }
        }
        if self.have_cursor
            && self.cursor_index > server.echo_ack
            && self.cursor_row < s.rows
            && self.cursor_col < s.cols
        {
            s.cursor_row = self.cursor_row;
            s.cursor_col = self.cursor_col;
        }
        s
    }

    /// Number of currently-active (unconfirmed) cell predictions.
    pub fn active_predictions(&self) -> usize {
        self.cells.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::screen::Screen;

    fn screen_with_ack(cols: u16, rows: u16, ack: u64) -> Screen {
        let mut s = Screen::blank(cols, rows);
        s.echo_ack = ack;
        s
    }

    #[test]
    fn predicts_typed_char_immediately() {
        let mut p = PredictionEngine::new(PredictMode::Always);
        let base = screen_with_ack(20, 3, 0);
        p.new_user_bytes(b"hi", &base, 2);
        let shown = p.predicted_screen(&base);
        assert_eq!(shown.cell(0, 0).unwrap().c, 'h');
        assert_eq!(shown.cell(0, 1).unwrap().c, 'i');
        assert_eq!(shown.cursor_col, 2);
    }

    #[test]
    fn multibyte_utf8_not_split() {
        let mut p = PredictionEngine::new(PredictMode::Always);
        let base = screen_with_ack(20, 3, 0);
        // "ü" = 0xC3 0xBC; feed the bytes in two separate chunks.
        p.new_user_bytes(&[0xC3], &base, 1);
        assert_eq!(
            p.active_predictions(),
            0,
            "no glyph until the char is complete"
        );
        p.new_user_bytes(&[0xBC], &base, 1);
        let shown = p.predicted_screen(&base);
        assert_eq!(
            shown.cell(0, 0).unwrap().c,
            'ü',
            "complete char predicted, not corrupted"
        );
    }

    #[test]
    fn correct_prediction_culled_when_server_catches_up() {
        let mut p = PredictionEngine::new(PredictMode::Always);
        let base = screen_with_ack(20, 3, 0);
        p.new_user_bytes(b"x", &base, 1);
        assert_eq!(p.active_predictions(), 1);

        // Server confirms input index 1 with a screen that actually shows 'x'.
        let mut confirmed = screen_with_ack(20, 3, 1);
        confirmed.cells[0].c = 'x';
        p.new_server_screen(&confirmed);
        assert_eq!(p.active_predictions(), 0, "confirmed prediction removed");
    }

    #[test]
    fn misprediction_flushes_overlay() {
        let mut p = PredictionEngine::new(PredictMode::Always);
        let base = screen_with_ack(20, 3, 0);
        p.new_user_bytes(b"x", &base, 1);
        // Server applied input 1 but the screen shows something else (e.g. the
        // app swallowed the key) → prediction was wrong.
        let mut confirmed = screen_with_ack(20, 3, 1);
        confirmed.cells[0].c = 'Z';
        p.new_server_screen(&confirmed);
        assert_eq!(p.active_predictions(), 0, "misprediction flushed");
        // Display falls back to the true server screen.
        assert_eq!(p.predicted_screen(&confirmed).cell(0, 0).unwrap().c, 'Z');
    }

    /// Port of mosh's prediction-unicode.test: typing multibyte UTF-8 with
    /// prediction enabled must never produce a corrupted/replacement glyph, even
    /// when bytes of one character arrive in separate reads.
    #[test]
    fn prediction_unicode_no_corruption() {
        let mut p = PredictionEngine::new(PredictMode::Always);
        let base = screen_with_ack(40, 2, 0);
        // "glück faĩl": ü = U+00FC (C3 BC), ĩ = U+0129 (C4 A9).
        let input = "glück faĩl".as_bytes().to_vec();
        // Deliver one byte at a time — the worst case for UTF-8 splitting.
        for (i, b) in input.iter().enumerate() {
            p.new_user_bytes(&[*b], &base, (i + 1) as u64);
        }
        let shown = p.predicted_screen(&base);
        let line: String = (0..10).map(|c| shown.cell(0, c).unwrap().c).collect();
        assert_eq!(
            line, "glück faĩl",
            "predicted text must be exact, uncorrupted UTF-8"
        );
        // No replacement characters anywhere.
        assert!(
            shown.cells.iter().all(|cell| cell.c != '\u{fffd}'),
            "no U+FFFD replacement characters"
        );
    }

    #[test]
    fn adaptive_mode_gates_on_srtt() {
        let mut p = PredictionEngine::new(PredictMode::Adaptive);
        let base = screen_with_ack(20, 2, 0);
        p.new_user_bytes(b"x", &base, 1);
        // Fast link: predictions tracked but not displayed.
        p.set_srtt(5.0);
        assert_eq!(p.predicted_screen(&base).cell(0, 0).unwrap().c, ' ');
        // Laggy link: now the prediction is shown.
        p.set_srtt(120.0);
        assert_eq!(p.predicted_screen(&base).cell(0, 0).unwrap().c, 'x');
    }

    #[test]
    fn tentative_predictions_are_underlined() {
        let mut p = PredictionEngine::new(PredictMode::Always);
        let base = screen_with_ack(20, 2, 0);
        p.new_user_bytes(b"x", &base, 1);
        let shown = p.predicted_screen(&base);
        assert_ne!(
            shown.cell(0, 0).unwrap().flags & crate::screen::F_UNDERLINE,
            0,
            "tentative prediction underlined"
        );
        p.set_flagging(false);
        assert_eq!(
            p.predicted_screen(&base).cell(0, 0).unwrap().flags & crate::screen::F_UNDERLINE,
            0,
            "underline disabled"
        );
    }

    #[test]
    fn glitch_suppresses_then_clears() {
        let mut p = PredictionEngine::new(PredictMode::Always);
        let base = screen_with_ack(20, 2, 0);
        p.new_user_bytes(b"x", &base, 1);
        // Misprediction: the server applied input 1 but shows 'Z'.
        let mut bad = screen_with_ack(20, 2, 1);
        bad.cells[0].c = 'Z';
        p.new_server_screen(&bad);
        // Glitch active: a fresh prediction is suppressed (server shown instead).
        p.new_user_bytes(b"y", &bad, 2);
        assert_eq!(p.predicted_screen(&bad).cell(0, 0).unwrap().c, 'Z');
        // The server confirms 'y' (input 2) → no contradiction → glitch clears.
        let mut good = screen_with_ack(20, 2, 2);
        good.cells[0].c = 'y';
        p.new_server_screen(&good);
        // Predictions display again.
        p.new_user_bytes(b"z", &good, 3);
        assert_eq!(p.predicted_screen(&good).cell(0, 0).unwrap().c, 'z');
    }

    #[test]
    fn predicts_wide_char_with_spacer() {
        let mut p = PredictionEngine::new(PredictMode::Always);
        let base = screen_with_ack(20, 2, 0);
        p.new_user_bytes("世".as_bytes(), &base, 1);
        let shown = p.predicted_screen(&base);
        assert_eq!(shown.cell(0, 0).unwrap().c, '世');
        assert_eq!(shown.cell(0, 1).unwrap().c, ' '); // spacer
                                                      // Cursor advanced by the full display width.
        assert_eq!(shown.cursor_col, 2);
    }

    #[test]
    fn escape_sequence_abandons_prediction() {
        let mut p = PredictionEngine::new(PredictMode::Always);
        let base = screen_with_ack(20, 3, 0);
        p.new_user_bytes(b"a", &base, 1);
        assert_eq!(p.active_predictions(), 1);
        p.new_user_bytes(b"\x1b[A", &base, 2); // arrow key → unpredictable
        assert_eq!(p.active_predictions(), 0, "escape flushes predictions");
    }
}
