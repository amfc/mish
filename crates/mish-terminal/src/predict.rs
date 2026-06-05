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

/// Number of *credited-correct* predictions (correct AND they changed the
/// screen) that must accumulate before [`PredictMode::Adaptive`] will display
/// predictions on a link whose SRTT is below the trigger. This is mosh's
/// "earn confidence from the track record" idea: don't speculate on a link/app
/// we have no evidence is predictable, but once a run of predictions has proven
/// correct, show them even on a marginal link. A misprediction resets it to 0.
const CONFIDENCE_TRIGGER: u32 = 10;

/// Cap so confidence can't grow unboundedly (and so a recent misprediction's
/// reset meaningfully delays re-enabling, rather than being instantly refilled).
const CONFIDENCE_CAP: u32 = 20;

/// A single input batch larger than this is treated as a paste (or other bulk
/// data) and **not** predicted: speculating on a hundreds-of-bytes blob just
/// produces a flickery, usually-wrong overlay. Mirrors mosh's
/// `bool paste = bytes_read > 100` in `stmclient.cc::process_user_input`.
const PASTE_THRESHOLD: usize = 100;

/// A prediction still unconfirmed this long (ms) is "glitchy": the link is slow
/// enough that the user should see their speculative echo even on an otherwise
/// quiet/fast-SRTT link. Forces the overlay on. (mosh `GLITCH_THRESHOLD`.)
const GLITCH_THRESHOLD_MS: u64 = 250;
/// Quick confirmations needed to cure the glitch trigger back to zero
/// (mosh `GLITCH_REPAIR_COUNT`); also the level above which we additionally
/// underline (a "really big glitch").
const GLITCH_REPAIR_COUNT: u32 = 10;
/// Minimum spacing (ms) between glitch-trigger decrements, so a burst of quick
/// confirmations in one frame cures it gradually (mosh `GLITCH_REPAIR_MININTERVAL`).
const GLITCH_REPAIR_MININTERVAL_MS: u64 = 150;
/// A prediction unconfirmed this long (ms) is bad enough to both display *and*
/// underline, signalling the user that the link has stalled (mosh
/// `GLITCH_FLAG_THRESHOLD`).
const GLITCH_FLAG_THRESHOLD_MS: u64 = 5000;

/// A glyph that reads as blank when measuring a line's content extent (a space
/// or the default/empty cell), so trailing blanks aren't treated as content to
/// shift on an insert.
fn is_blank_glyph(c: char) -> bool {
    c == ' ' || c == '\0'
}

/// Parse state for an in-progress input escape sequence, so we can predict the
/// cursor-moving arrow keys (`ESC [ C/D`, `ESC O C/D`) instead of abandoning
/// prediction the moment an escape byte appears. Persists across input batches
/// (a sequence may be split across reads).
#[derive(Clone, Copy, PartialEq, Eq)]
enum EscPhase {
    /// Not inside an escape sequence.
    None,
    /// Saw `ESC`.
    Esc,
    /// Saw `ESC [` (CSI).
    Csi,
    /// Saw `ESC O` (SS3, application-cursor-keys form).
    Ss3,
}

#[derive(Clone)]
struct CellPrediction {
    row: u16,
    col: u16,
    cell: Cell,
    /// Client input index (`UserStream::total()`) at which this was predicted.
    input_index: u64,
    /// Whether this prediction *changed* the displayed cell (vs. matching what
    /// was already there). Only credited predictions build confidence — a
    /// prediction that merely re-asserts the existing glyph is no evidence that
    /// speculation is working (mosh's `CorrectNoCredit`).
    credit: bool,
    /// Monotonic time (ms) this prediction was made, for the long-pending
    /// "glitch" aging (mosh's `ConditionalOverlay::prediction_time`).
    predicted_at_ms: u64,
}

/// Speculative overlay of unconfirmed local input.
pub struct PredictionEngine {
    mode: PredictMode,
    cells: Vec<CellPrediction>,
    cursor_row: u16,
    cursor_col: u16,
    cursor_index: u64,
    /// Time (ms) the cursor prediction was last moved, for glitch aging.
    cursor_at_ms: u64,
    have_cursor: bool,
    /// Buffer for an incomplete trailing UTF-8 sequence.
    utf8: Vec<u8>,
    /// Once an unpredictable byte (escape/control) is seen, suppress prediction
    /// for the rest of the current input batch (the escape sequence's remaining
    /// bytes must not be echoed as text).
    suppress: bool,
    /// In-progress input escape-sequence parse (for arrow-key prediction).
    esc: EscPhase,
    /// Latest SRTT estimate (ms), for adaptive gating.
    srtt_ms: f64,
    /// Underline tentative (unconfirmed) predictions so they read as speculative
    /// (mosh's prediction "flagging").
    flagging: bool,
    /// After a misprediction, suppress the overlay until the next clean server
    /// update, to avoid flicker. Approximates mosh's epoch/tentative resync:
    /// once we've diverged, show the truth until the server agrees again.
    resync_suppress: bool,
    /// Long-pending-prediction trigger (mosh's `glitch_trigger`). A *counter*,
    /// not a boolean: while > 0 the overlay is forced on even on a fast/quiet
    /// link (the user's keystrokes are visibly queued); above
    /// [`GLITCH_REPAIR_COUNT`] it also underlines. Quick confirmations decrement
    /// it; a stalled prediction escalates it (see [`Self::advance`]).
    glitch_trigger: u32,
    /// Time (ms) of the last glitch-curing quick confirmation, to rate-limit
    /// decrements (mosh's `last_quick_confirmation`).
    last_quick_confirmation_ms: u64,
    /// Accumulated credited-correct predictions (see [`CONFIDENCE_TRIGGER`]).
    confidence: u32,
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
            cursor_at_ms: 0,
            have_cursor: false,
            utf8: Vec::new(),
            suppress: false,
            esc: EscPhase::None,
            srtt_ms: 0.0,
            flagging: true,
            resync_suppress: false,
            glitch_trigger: 0,
            last_quick_confirmation_ms: 0,
            confidence: 0,
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
        if self.resync_suppress {
            return false; // suppressed after a recent misprediction
        }
        match self.mode {
            PredictMode::Never => false,
            PredictMode::Always => true,
            // Show on a laggy link (immediate benefit), once we've built a track
            // record of correct predictions on this link/app (so a borderline
            // link still gets snappy echo), OR while a prediction has been
            // pending long enough to look stalled (glitch trigger) — then we
            // surface the speculation so typing doesn't appear to vanish.
            PredictMode::Adaptive => {
                self.srtt_ms >= ADAPTIVE_SRTT_TRIGGER_MS
                    || self.confidence >= CONFIDENCE_TRIGGER
                    || self.glitch_trigger > 0
            }
        }
    }

    /// Whether tentative predictions should be underlined right now: either the
    /// user/link preference ([`Self::set_flagging`], default on) or a severe
    /// glitch (a prediction pending past [`GLITCH_FLAG_THRESHOLD_MS`] pushed the
    /// trigger above [`GLITCH_REPAIR_COUNT`]).
    fn flag_predictions(&self) -> bool {
        self.flagging || self.glitch_trigger > GLITCH_REPAIR_COUNT
    }

    fn reset(&mut self) {
        // Clears the prediction overlay only. The UTF-8 decode buffer is
        // transport-level framing state owned by the decode loop — clearing it
        // here (reset is called mid-decode on an escape byte) would corrupt that
        // loop's indices.
        self.cells.clear();
        self.have_cursor = false;
    }

    /// Register local keystroke `bytes`, typed at client input index
    /// `input_index` (the `UserStream::total()` after appending them) at
    /// monotonic time `now_ms`, against the currently displayed `base` screen.
    pub fn new_user_bytes(&mut self, bytes: &[u8], base: &Screen, input_index: u64, now_ms: u64) {
        if self.mode == PredictMode::Never {
            return;
        }
        // Bulk data (a paste) is not predicted: a large speculative overlay just
        // flickers and is usually wrong. Drop any in-flight overlay and skip the
        // batch entirely (mosh's `paste` guard) — the real screen shows the truth.
        if bytes.len() > PASTE_THRESHOLD {
            self.reset();
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
                        self.predict_char(ch, input_index, base, now_ms);
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
                            self.predict_char(ch, input_index, base, now_ms);
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

    fn predict_char(&mut self, ch: char, input_index: u64, base: &Screen, now_ms: u64) {
        // Continue an in-progress escape sequence (arrow-key prediction). Persists
        // across batches, so check it before the per-batch `suppress` gate.
        if self.esc != EscPhase::None {
            self.continue_escape(ch, input_index, now_ms);
            return;
        }
        if self.suppress {
            return; // inside an unpredictable (escape) sequence
        }
        match ch {
            // Carriage return: go to column 0.
            '\r' => {
                self.cursor_col = 0;
                self.cursor_index = input_index;
                self.cursor_at_ms = now_ms;
            }
            // Line feed: next row (predicting scroll is unsafe, so clamp).
            '\n' => {
                self.cursor_col = 0;
                if self.cursor_row + 1 < self.rows {
                    self.cursor_row += 1;
                }
                self.cursor_index = input_index;
                self.cursor_at_ms = now_ms;
            }
            // Backspace / delete: move left and predict an erased cell.
            '\u{8}' | '\u{7f}' => {
                self.cursor_col = self.cursor_col.saturating_sub(1);
                let cell = Cell {
                    c: ' ',
                    ..Cell::default()
                };
                self.push_cell(cell, input_index, base, now_ms);
                self.cursor_index = input_index;
                self.cursor_at_ms = now_ms;
            }
            // Tab: advance to the next multiple of 8.
            '\t' => {
                let next = ((self.cursor_col / 8) + 1) * 8;
                self.cursor_col = next.min(self.cols - 1);
                self.cursor_index = input_index;
                self.cursor_at_ms = now_ms;
            }
            // Escape: begin an escape sequence — it may be an arrow key we can
            // predict (handled by `continue_escape`); we only abandon if it turns
            // out to be something else.
            '\u{1b}' => {
                self.esc = EscPhase::Esc;
            }
            // Any other control character: we can't safely predict the effect, so
            // abandon speculation and fall back to the real screen.
            c if (c as u32) < 0x20 => {
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
                        self.push_cell(wide, input_index, base, now_ms);
                        self.advance_cursor();
                        let spacer = Cell {
                            c: ' ',
                            ..Cell::default()
                        };
                        self.push_cell(spacer, input_index, base, now_ms);
                        self.advance_cursor();
                    }
                    _ => {
                        // Insert mode (shells' default readline): typing in the
                        // middle of a line shifts the rest right, so predict that
                        // shift before placing the glyph.
                        self.insert_char(c, input_index, base, now_ms);
                        self.advance_cursor();
                    }
                }
                self.cursor_index = input_index;
                self.cursor_at_ms = now_ms;
            }
        }
    }

    /// Push a prediction at the cursor (used for backspace/wide-char glyphs).
    fn push_cell(&mut self, cell: Cell, input_index: u64, base: &Screen, now_ms: u64) {
        self.set_prediction(
            self.cursor_row,
            self.cursor_col,
            cell,
            input_index,
            base,
            now_ms,
        );
    }

    /// Place (or replace) a cell prediction at an explicit position.
    fn set_prediction(
        &mut self,
        row: u16,
        col: u16,
        cell: Cell,
        input_index: u64,
        base: &Screen,
        now_ms: u64,
    ) {
        // Credit this prediction only if it changes what's displayed there
        // (mosh's `CorrectNoCredit`): a prediction that merely re-asserts the
        // existing glyph is no evidence speculation is working.
        let credit = self.displayed_cell(row, col, base).c != cell.c;
        self.cells.retain(|p| !(p.row == row && p.col == col));
        self.cells.push(CellPrediction {
            row,
            col,
            cell,
            input_index,
            credit,
            predicted_at_ms: now_ms,
        });
    }

    /// The cell currently shown at `(row, col)`: an active prediction if present,
    /// else the server's cell, else a blank.
    fn displayed_cell(&self, row: u16, col: u16, base: &Screen) -> Cell {
        if let Some(p) = self.cells.iter().find(|p| p.row == row && p.col == col) {
            p.cell.clone()
        } else {
            base.cell(row, col).cloned().unwrap_or_default()
        }
    }

    /// Insert `c` at the cursor in insert mode: shift the line's existing content
    /// from the cursor rightward by one, then place the glyph. Only the actual
    /// content (up to the rightmost non-blank cell) is shifted, so typing at the
    /// end of a line stays a single-cell prediction (no whole-row churn).
    fn insert_char(&mut self, c: char, input_index: u64, base: &Screen, now_ms: u64) {
        let (row, col) = (self.cursor_row, self.cursor_col);
        if let Some(end) = self.line_content_end(row, base) {
            // Only shift when there is content *strictly to the right* of the
            // cursor — a genuine mid-line insert. Typing at (or past) the end of a
            // line, or over the single cell under the cursor, is an overwrite: the
            // server replaces that cell rather than inserting, so shifting there
            // would just cause a misprediction.
            if col < end {
                // Shift [col, end] right by one (dropping anything past the edge);
                // process right-to-left so each source is read before it's moved.
                let last = (end + 1).min(self.cols - 1);
                for p in (col + 1..=last).rev() {
                    let src = self.displayed_cell(row, p - 1, base);
                    self.set_prediction(row, p, src, input_index, base, now_ms);
                }
            }
        }
        let cell = Cell {
            c,
            ..Cell::default()
        };
        self.set_prediction(row, col, cell, input_index, base, now_ms);
    }

    /// Column of the rightmost non-blank cell on `row` (predictions over base), or
    /// `None` if the row is blank.
    fn line_content_end(&self, row: u16, base: &Screen) -> Option<u16> {
        (0..self.cols)
            .rev()
            .find(|&p| !is_blank_glyph(self.displayed_cell(row, p, base).c))
    }

    /// Continue parsing an input escape sequence, predicting the left/right arrow
    /// keys (which just move the cursor) and abandoning prediction for anything
    /// else (as before — we can't safely predict arbitrary escape effects).
    fn continue_escape(&mut self, ch: char, input_index: u64, now_ms: u64) {
        match (self.esc, ch) {
            (EscPhase::Esc, '[') => self.esc = EscPhase::Csi,
            (EscPhase::Esc, 'O') => self.esc = EscPhase::Ss3,
            (EscPhase::Csi | EscPhase::Ss3, 'C') => {
                self.esc = EscPhase::None;
                self.predict_cursor_h(true, input_index, now_ms); // right
            }
            (EscPhase::Csi | EscPhase::Ss3, 'D') => {
                self.esc = EscPhase::None;
                self.predict_cursor_h(false, input_index, now_ms); // left
            }
            _ => {
                // Not an arrow key — abandon prediction for the rest of the batch.
                self.esc = EscPhase::None;
                self.reset();
                self.suppress = true;
            }
        }
    }

    /// Predict a one-column cursor move (right if `right`, else left), clamped to
    /// the screen — no cell changes.
    fn predict_cursor_h(&mut self, right: bool, input_index: u64, now_ms: u64) {
        if right {
            if self.cursor_col + 1 < self.cols {
                self.cursor_col += 1;
            }
        } else {
            self.cursor_col = self.cursor_col.saturating_sub(1);
        }
        self.cursor_index = input_index;
        self.cursor_at_ms = now_ms;
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

    /// Incorporate a freshly received server screen received at `now_ms`:
    /// validate predictions the server has now applied (`input_index <=
    /// screen.echo_ack`, mosh's `late_ack`) and cull or, on a misprediction,
    /// flush everything.
    pub fn new_server_screen(&mut self, screen: &Screen, now_ms: u64) {
        if self.mode == PredictMode::Never {
            self.reset();
            return;
        }
        let ack = screen.echo_ack;

        // A mispredicted, now-confirmed cell means our speculation diverged from
        // reality: drop all predictions and resync to the server.
        let cell_mispredict = self.cells.iter().any(|p| {
            p.input_index <= ack
                && screen
                    .cell(p.row, p.col)
                    .map(|actual| actual.c != p.cell.c)
                    .unwrap_or(true)
        });
        // Likewise for the cursor: a confirmed cursor prediction that doesn't
        // match the server's real cursor is a misprediction (mosh's
        // `ConditionalCursorMove::get_validity` → `IncorrectOrExpired`). Without
        // this a mispredicted cursor would silently linger until the next move.
        let cursor_mispredict = self.have_cursor
            && self.cursor_index <= ack
            && (screen.cursor_row != self.cursor_row || screen.cursor_col != self.cursor_col);
        if cell_mispredict || cursor_mispredict {
            self.reset();
            self.resync_suppress = true; // suppress overlay until the next clean update
            self.confidence = 0; // track record broken — re-earn confidence
            return;
        }

        // A clean update clears the post-misprediction suppression.
        self.resync_suppress = false;

        // Confirmed predictions (input_index <= ack) all matched the server, so
        // each *credited* one (it actually changed the screen) is evidence that
        // speculation is working: build confidence (capped). CorrectNoCredit
        // confirmations — predictions that just re-asserted the existing glyph —
        // contribute nothing.
        let credited = self
            .cells
            .iter()
            .filter(|p| p.input_index <= ack && p.credit)
            .count() as u32;
        self.confidence = (self.confidence + credited).min(CONFIDENCE_CAP);

        // Quick confirmations slowly cure the glitch trigger: if any prediction
        // was confirmed well within GLITCH_THRESHOLD, the link is keeping up, so
        // step the trigger down (rate-limited, mosh's GLITCH_REPAIR_MININTERVAL).
        let quick_confirm = self
            .cells
            .iter()
            .any(|p| p.input_index <= ack && now_ms.saturating_sub(p.predicted_at_ms) < GLITCH_THRESHOLD_MS);
        if quick_confirm
            && self.glitch_trigger > 0
            && now_ms.saturating_sub(GLITCH_REPAIR_MININTERVAL_MS) >= self.last_quick_confirmation_ms
        {
            self.glitch_trigger -= 1;
            self.last_quick_confirmation_ms = now_ms;
        }

        // Drop confirmed-correct predictions (the real screen now shows them).
        self.cells.retain(|p| p.input_index > ack);
        if self.cursor_index <= ack {
            self.have_cursor = false;
        }
    }

    /// Advance the engine's notion of time without new input or a server frame
    /// (called each repaint, incl. the idle status-banner tick). This is where a
    /// *pending* prediction that has gone unconfirmed too long escalates the
    /// glitch trigger — mosh's `cull()` Pending case, driven by `wait_time()`'s
    /// 50 ms poll. The effect: on a stalled link the user's speculative echo is
    /// surfaced (and, past [`GLITCH_FLAG_THRESHOLD_MS`], underlined) so typing
    /// never appears to vanish.
    pub fn advance(&mut self, now_ms: u64) {
        // Age of the oldest still-pending prediction (cells + cursor).
        let oldest = self
            .cells
            .iter()
            .map(|p| p.predicted_at_ms)
            .chain(self.have_cursor.then_some(self.cursor_at_ms))
            .min();
        if let Some(t) = oldest {
            let age = now_ms.saturating_sub(t);
            if age >= GLITCH_FLAG_THRESHOLD_MS {
                self.glitch_trigger = GLITCH_REPAIR_COUNT * 2; // display *and* underline
            } else if age >= GLITCH_THRESHOLD_MS && self.glitch_trigger < GLITCH_REPAIR_COUNT {
                self.glitch_trigger = GLITCH_REPAIR_COUNT; // just display
            }
        }
    }

    /// Accumulated confidence (credited-correct predictions); for tests/observability.
    pub fn confidence(&self) -> u32 {
        self.confidence
    }

    /// Current glitch-trigger level (long-pending-prediction counter); for
    /// tests/observability.
    pub fn glitch_trigger(&self) -> u32 {
        self.glitch_trigger
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
                    if self.flag_predictions() {
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

    /// A blank server screen with a given echo_ack and cursor column — the
    /// common shape for confirming a prediction that advanced the cursor.
    fn confirmed_screen(cols: u16, rows: u16, ack: u64, cursor_col: u16) -> Screen {
        let mut s = Screen::blank(cols, rows);
        s.echo_ack = ack;
        s.cursor_col = cursor_col;
        s
    }

    #[test]
    fn predicts_typed_char_immediately() {
        let mut p = PredictionEngine::new(PredictMode::Always);
        let base = screen_with_ack(20, 3, 0);
        p.new_user_bytes(b"hi", &base, 2, 0);
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
        p.new_user_bytes(&[0xC3], &base, 1, 0);
        assert_eq!(
            p.active_predictions(),
            0,
            "no glyph until the char is complete"
        );
        p.new_user_bytes(&[0xBC], &base, 1, 0);
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
        p.new_user_bytes(b"x", &base, 1, 0);
        assert_eq!(p.active_predictions(), 1);

        // Server confirms input index 1 with a screen that shows 'x' and the
        // cursor advanced to where we predicted it (col 1).
        let mut confirmed = confirmed_screen(20, 3, 1, 1);
        confirmed.cells[0].c = 'x';
        p.new_server_screen(&confirmed, 10);
        assert_eq!(p.active_predictions(), 0, "confirmed prediction removed");
    }

    #[test]
    fn misprediction_flushes_overlay() {
        let mut p = PredictionEngine::new(PredictMode::Always);
        let base = screen_with_ack(20, 3, 0);
        p.new_user_bytes(b"x", &base, 1, 0);
        // Server applied input 1 but the screen shows something else (e.g. the
        // app swallowed the key) → prediction was wrong.
        let mut confirmed = screen_with_ack(20, 3, 1);
        confirmed.cells[0].c = 'Z';
        p.new_server_screen(&confirmed, 10);
        assert_eq!(p.active_predictions(), 0, "misprediction flushed");
        // Display falls back to the true server screen.
        assert_eq!(p.predicted_screen(&confirmed).cell(0, 0).unwrap().c, 'Z');
    }

    /// A correct cell prediction whose *cursor* the server placed elsewhere is a
    /// misprediction (mosh's `ConditionalCursorMove::get_validity`): the overlay
    /// is flushed so a stale predicted cursor can't linger.
    #[test]
    fn cursor_misprediction_triggers_resync() {
        let mut p = PredictionEngine::new(PredictMode::Always);
        let base = screen_with_ack(20, 3, 0);
        p.new_user_bytes(b"x", &base, 1, 0);
        assert_eq!(p.active_predictions(), 1);
        // The cell 'x' is right, but the server's cursor ended up at col 5, not
        // the col 1 we predicted.
        let mut confirmed = confirmed_screen(20, 3, 1, 5);
        confirmed.cells[0].c = 'x';
        p.new_server_screen(&confirmed, 10);
        assert_eq!(
            p.active_predictions(),
            0,
            "cursor misprediction flushes the overlay"
        );
    }

    /// Bulk input (a paste) is not predicted and drops any existing overlay —
    /// speculating on hundreds of bytes just flickers (mosh's paste guard).
    #[test]
    fn paste_guard_skips_bulk_input() {
        let mut p = PredictionEngine::new(PredictMode::Always);
        let base = screen_with_ack(20, 4, 0);
        p.new_user_bytes(b"x", &base, 1, 0);
        assert_eq!(p.active_predictions(), 1);

        let paste = vec![b'a'; PASTE_THRESHOLD + 1];
        p.new_user_bytes(&paste, &base, 2, 1);
        assert_eq!(p.active_predictions(), 0, "paste is not predicted");
        assert_eq!(
            p.predicted_screen(&base).cell(0, 0).unwrap().c,
            ' ',
            "paste leaves the real screen showing"
        );
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
            p.new_user_bytes(&[*b], &base, (i + 1) as u64, 0);
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
        p.new_user_bytes(b"x", &base, 1, 0);
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
        p.new_user_bytes(b"x", &base, 1, 0);
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
    fn resync_suppresses_then_clears() {
        let mut p = PredictionEngine::new(PredictMode::Always);
        let base = screen_with_ack(20, 2, 0);
        p.new_user_bytes(b"x", &base, 1, 0);
        // Misprediction: the server applied input 1 but shows 'Z'.
        let mut bad = screen_with_ack(20, 2, 1);
        bad.cells[0].c = 'Z';
        p.new_server_screen(&bad, 10);
        // Suppressed: a fresh prediction is hidden (server shown instead).
        p.new_user_bytes(b"y", &bad, 2, 20);
        assert_eq!(p.predicted_screen(&bad).cell(0, 0).unwrap().c, 'Z');
        // The server confirms 'y' at (0,0) with the cursor advanced to col 1 →
        // no contradiction → suppression clears.
        let mut good = confirmed_screen(20, 2, 2, 1);
        good.cells[0].c = 'y';
        p.new_server_screen(&good, 30);
        // Predictions display again: typing 'z' at the (server) cursor col 1.
        p.new_user_bytes(b"z", &good, 3, 40);
        assert_eq!(p.predicted_screen(&good).cell(0, 1).unwrap().c, 'z');
    }

    #[test]
    fn predicts_wide_char_with_spacer() {
        let mut p = PredictionEngine::new(PredictMode::Always);
        let base = screen_with_ack(20, 2, 0);
        p.new_user_bytes("世".as_bytes(), &base, 1, 0);
        let shown = p.predicted_screen(&base);
        assert_eq!(shown.cell(0, 0).unwrap().c, '世');
        assert_eq!(shown.cell(0, 1).unwrap().c, ' '); // spacer
                                                      // Cursor advanced by the full display width.
        assert_eq!(shown.cursor_col, 2);
    }

    /// Confidence built from a track record of credited-correct predictions lets
    /// Adaptive mode display predictions even on a link below the SRTT trigger.
    #[test]
    fn confidence_enables_adaptive_below_srtt_trigger() {
        let mut p = PredictionEngine::new(PredictMode::Adaptive);
        p.set_srtt(5.0); // SRTT gate closed
        let (cols, rows) = (40u16, 2u16);

        for i in 1..=CONFIDENCE_TRIGGER as u64 {
            // Type a char into a fresh (blank) cell → a screen-changing prediction.
            let mut server = Screen::blank(cols, rows);
            server.echo_ack = i - 1;
            server.cursor_col = (i - 1) as u16;
            p.new_user_bytes(b"a", &server, i, i * 10);

            // Server confirms it: that cell really shows 'a', cursor advanced.
            let mut confirmed = Screen::blank(cols, rows);
            confirmed.echo_ack = i;
            confirmed.cells[(i - 1) as usize].c = 'a';
            confirmed.cursor_col = i as u16;
            p.new_server_screen(&confirmed, i * 10 + 5);
        }
        assert!(
            p.confidence() >= CONFIDENCE_TRIGGER,
            "confidence should accumulate from credited-correct predictions"
        );

        // SRTT still below the trigger, yet a fresh prediction now displays.
        let mut server = Screen::blank(cols, rows);
        server.echo_ack = CONFIDENCE_TRIGGER as u64;
        p.new_user_bytes(b"Z", &server, CONFIDENCE_TRIGGER as u64 + 1, 1000);
        assert_eq!(
            p.predicted_screen(&server).cell(0, 0).unwrap().c,
            'Z',
            "confidence enables the overlay despite low SRTT"
        );
    }

    /// A prediction that merely re-asserts the glyph already on screen earns no
    /// credit (mosh's CorrectNoCredit), so it doesn't build confidence.
    #[test]
    fn correct_no_credit_does_not_build_confidence() {
        let mut p = PredictionEngine::new(PredictMode::Adaptive);
        let mut server = Screen::blank(20, 2);
        server.cells[0].c = 'a';
        p.new_user_bytes(b"a", &server, 1, 0); // predict 'a' where 'a' already is
        let mut confirmed = server.clone();
        confirmed.echo_ack = 1; // still shows 'a' — correct, but no visible change
        confirmed.cursor_col = 1; // cursor advanced as predicted
        p.new_server_screen(&confirmed, 10);
        assert_eq!(
            p.confidence(),
            0,
            "matching the existing glyph earns no confidence"
        );
    }

    /// A misprediction wipes the accumulated confidence (the track record is gone).
    #[test]
    fn misprediction_resets_confidence() {
        let mut p = PredictionEngine::new(PredictMode::Adaptive);
        // Earn one credit.
        let mut server = Screen::blank(20, 2);
        server.cursor_col = 0;
        p.new_user_bytes(b"a", &server, 1, 0);
        let mut good = confirmed_screen(20, 2, 1, 1);
        good.cells[0].c = 'a';
        p.new_server_screen(&good, 10);
        assert_eq!(p.confidence(), 1);

        // Now mispredict: type 'b', but the server shows 'X'.
        p.new_user_bytes(b"b", &good, 2, 20);
        let mut bad = Screen::blank(20, 2);
        bad.echo_ack = 2;
        bad.cells[1].c = 'X';
        p.new_server_screen(&bad, 30);
        assert_eq!(p.confidence(), 0, "misprediction resets confidence");
    }

    #[test]
    fn escape_sequence_abandons_prediction() {
        let mut p = PredictionEngine::new(PredictMode::Always);
        let base = screen_with_ack(20, 3, 0);
        p.new_user_bytes(b"a", &base, 1, 0);
        assert_eq!(p.active_predictions(), 1);
        p.new_user_bytes(b"\x1b[A", &base, 2, 10); // up arrow → still unpredictable
        assert_eq!(p.active_predictions(), 0, "escape flushes predictions");
    }

    /// Left/right arrow keys (CSI and SS3 forms) are predicted as cursor moves,
    /// instead of abandoning the overlay — so line editing stays snappy on a
    /// laggy link.
    #[test]
    fn predicts_arrow_key_cursor_moves() {
        let mut p = PredictionEngine::new(PredictMode::Always);
        let base = screen_with_ack(20, 3, 0);
        p.new_user_bytes(b"abc", &base, 3, 0);
        assert_eq!(p.predicted_screen(&base).cursor_col, 3);

        // Left arrow (CSI form): cursor moves left, overlay kept.
        p.new_user_bytes(b"\x1b[D", &base, 4, 0);
        let shown = p.predicted_screen(&base);
        assert_eq!(shown.cursor_col, 2, "left arrow moved the cursor");
        assert_eq!(shown.cell(0, 0).unwrap().c, 'a', "typed glyphs survive the arrow");

        // Right arrow (SS3 / application-cursor-keys form): back to col 3.
        p.new_user_bytes(b"\x1bOC", &base, 5, 0);
        assert_eq!(
            p.predicted_screen(&base).cursor_col,
            3,
            "right arrow moved the cursor"
        );
    }

    /// Typing in the *middle* of a line is predicted as an insert that shifts the
    /// rest of the line right (shells' default readline insert mode), not an
    /// overwrite.
    #[test]
    fn predicts_insert_shift_mid_line() {
        let mut p = PredictionEngine::new(PredictMode::Always);
        let mut base = screen_with_ack(20, 2, 0);
        base.cells[0].c = 'X';
        base.cells[1].c = 'Y';
        base.cells[2].c = 'Z';
        base.cursor_col = 1; // between X and Y

        p.new_user_bytes(b"a", &base, 1, 0);
        let shown = p.predicted_screen(&base);
        assert_eq!(shown.cell(0, 0).unwrap().c, 'X', "before the cursor: unchanged");
        assert_eq!(shown.cell(0, 1).unwrap().c, 'a', "glyph inserted at the cursor");
        assert_eq!(shown.cell(0, 2).unwrap().c, 'Y', "rest of the line shifted right");
        assert_eq!(shown.cell(0, 3).unwrap().c, 'Z', "…and Z too");
        assert_eq!(shown.cursor_col, 2, "cursor advanced past the insert");
    }

    /// Typing at the end of a line stays a single-cell overwrite (no spurious
    /// whole-row shift), so the common case is cheap and never mispredicts.
    #[test]
    fn end_of_line_typing_does_not_shift() {
        let mut p = PredictionEngine::new(PredictMode::Always);
        let mut base = screen_with_ack(20, 2, 0);
        base.cells[0].c = 'X';
        base.cells[1].c = 'Y';
        base.cursor_col = 2; // just past the content

        p.new_user_bytes(b"z", &base, 1, 0);
        assert_eq!(
            p.active_predictions(),
            1,
            "appending at the end is a single prediction, not a row shift"
        );
        assert_eq!(p.predicted_screen(&base).cell(0, 2).unwrap().c, 'z');
    }

    /// A prediction left unconfirmed past GLITCH_THRESHOLD escalates the glitch
    /// trigger, which forces the overlay on even on a fast-SRTT Adaptive link —
    /// so the user's typing never appears to vanish on a momentary stall.
    #[test]
    fn long_pending_prediction_forces_display() {
        let mut p = PredictionEngine::new(PredictMode::Adaptive);
        p.set_srtt(5.0); // SRTT gate closed, no confidence yet
        let base = screen_with_ack(20, 2, 0);
        p.new_user_bytes(b"x", &base, 1, 0);

        // Recently predicted, fast link → not shown.
        p.advance(100);
        assert_eq!(p.glitch_trigger(), 0);
        assert_eq!(p.predicted_screen(&base).cell(0, 0).unwrap().c, ' ');

        // Still unconfirmed past the threshold → glitch forces it on.
        p.advance(400);
        assert!(p.glitch_trigger() > 0, "long-pending prediction escalates");
        assert_eq!(
            p.predicted_screen(&base).cell(0, 0).unwrap().c,
            'x',
            "stalled prediction surfaced despite low SRTT"
        );
    }

    /// A prediction pending past GLITCH_FLAG_THRESHOLD underlines even when
    /// flagging is otherwise off — signalling the link has stalled.
    #[test]
    fn severe_glitch_underlines_even_with_flagging_off() {
        let mut p = PredictionEngine::new(PredictMode::Always);
        p.set_flagging(false);
        let base = screen_with_ack(20, 2, 0);
        p.new_user_bytes(b"x", &base, 1, 0);
        assert_eq!(
            p.predicted_screen(&base).cell(0, 0).unwrap().flags & crate::screen::F_UNDERLINE,
            0,
            "no underline while flagging is off and the prediction is fresh"
        );

        p.advance(GLITCH_FLAG_THRESHOLD_MS + 1);
        assert!(p.glitch_trigger() > GLITCH_REPAIR_COUNT);
        assert_ne!(
            p.predicted_screen(&base).cell(0, 0).unwrap().flags & crate::screen::F_UNDERLINE,
            0,
            "a long-stalled prediction underlines to signal the glitch"
        );
    }

    /// Quick confirmations step the glitch trigger back down (rate-limited),
    /// mirroring mosh's GLITCH_REPAIR_COUNT/GLITCH_REPAIR_MININTERVAL cure.
    #[test]
    fn quick_confirmations_cure_glitch_trigger() {
        let mut p = PredictionEngine::new(PredictMode::Always);
        // Drive the trigger to its peak with a long-pending prediction, then
        // confirm it (late — no cure from a stale confirmation).
        let s0 = screen_with_ack(20, 2, 0);
        p.new_user_bytes(b"x", &s0, 1, 0);
        p.advance(GLITCH_FLAG_THRESHOLD_MS + 1);
        assert_eq!(p.glitch_trigger(), GLITCH_REPAIR_COUNT * 2);

        let mut confirmed = confirmed_screen(20, 2, 1, 1);
        confirmed.cells[0].c = 'x';
        p.new_server_screen(&confirmed, GLITCH_FLAG_THRESHOLD_MS + 1);
        assert_eq!(
            p.glitch_trigger(),
            GLITCH_REPAIR_COUNT * 2,
            "a stale (slow) confirmation does not cure the glitch"
        );

        // A run of fresh predict→confirm-within-250ms cycles, spaced past the
        // repair min-interval, decrements the trigger one notch per cycle.
        let mut prev = confirmed;
        let mut t = GLITCH_FLAG_THRESHOLD_MS + 1;
        for idx in 2u64..=4 {
            t += GLITCH_REPAIR_MININTERVAL_MS + 50;
            let col = prev.cursor_col;
            p.new_user_bytes(b"y", &prev, idx, t);
            let mut nc = prev.clone();
            nc.echo_ack = idx;
            nc.cells[col as usize].c = 'y';
            nc.cursor_col = col + 1;
            let before = p.glitch_trigger();
            p.new_server_screen(&nc, t + 20); // confirmed within GLITCH_THRESHOLD
            assert_eq!(
                p.glitch_trigger(),
                before - 1,
                "each quick confirmation cures one notch"
            );
            prev = nc;
        }
    }
}
