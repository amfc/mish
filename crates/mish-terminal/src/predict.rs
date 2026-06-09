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

/// SRTT (ms) thresholds for switching adaptive prediction on/off, as a
/// *hysteresis band* rather than a single cutoff (mosh's `SRTT_TRIGGER_HIGH` /
/// `SRTT_TRIGGER_LOW`). The overlay turns **on** once SRTT rises above HIGH and
/// turns **off** only once it falls back to/below LOW; in the band between, the
/// previous on/off state is held. A single threshold would flap the overlay on
/// and off frame-to-frame on a link hovering right at the cutoff — the band
/// prevents that.
const ADAPTIVE_SRTT_TRIGGER_HIGH_MS: f64 = 30.0;
const ADAPTIVE_SRTT_TRIGGER_LOW_MS: f64 = 20.0;

/// Number of *credited-correct* predictions (correct AND they changed the
/// screen) that must accumulate before [`PredictMode::Adaptive`] will display
/// predictions on a link whose SRTT is below the trigger. This is mosh's
/// "earn confidence from the track record" idea: don't speculate on a link/app
/// we have no evidence is predictable, but once a run of predictions has proven
/// correct, show them even on a marginal link. A misprediction resets it to 0.
const CONFIDENCE_TRIGGER: u32 = 10;

/// Window (ms) over which [`PredictionEngine::accuracy`] reports prediction
/// accuracy for the client status bar: recent enough to reflect the current
/// link/app, long enough to be a stable percentage. One minute, matching the
/// status bar's loss window.
const OUTCOME_WINDOW_MS: u64 = 60_000;

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

/// readline's default word definition: a "word" is a maximal run of
/// alphanumeric characters, everything else a delimiter. Used to predict the
/// word-wise cursor motions (`M-b`/`M-f`, Ctrl-arrow).
fn is_word_char(c: char) -> bool {
    c.is_alphanumeric()
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
    /// The prediction epoch this was made in (mosh's `tentative_until_epoch`).
    /// The prediction is only *displayed* once [`PredictionEngine::confirmed_epoch`]
    /// reaches this value — i.e. once a prediction in this epoch (or an earlier
    /// one) has been confirmed correct by the server. See the engine fields.
    epoch: u64,
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
    /// Prediction epoch the cursor move was made in (see `prediction_epoch`).
    cursor_epoch: u64,
    have_cursor: bool,
    /// Buffer for an incomplete trailing UTF-8 sequence.
    utf8: Vec<u8>,
    /// Once an unpredictable byte (escape/control) is seen, suppress prediction
    /// for the rest of the current input batch (the escape sequence's remaining
    /// bytes must not be echoed as text).
    suppress: bool,
    /// In-progress input escape-sequence parse (for cursor-motion prediction).
    esc: EscPhase,
    /// Accumulated CSI parameter bytes (digits and `;`) of the in-progress
    /// sequence, so a parameterised motion like `ESC [ 1 ; 5 C` (Ctrl-Right) or
    /// `ESC [ 4 ~` (End) can be distinguished from a bare arrow. Cleared when a
    /// fresh CSI begins; only ASCII digits/`;` are ever pushed.
    esc_params: Vec<u8>,
    /// Latest SRTT estimate (ms), for adaptive gating.
    srtt_ms: f64,
    /// Whether the SRTT-based adaptive trigger is currently *latched on*. Updated
    /// with hysteresis in [`Self::set_srtt`] (band between
    /// [`ADAPTIVE_SRTT_TRIGGER_LOW_MS`] and [`ADAPTIVE_SRTT_TRIGGER_HIGH_MS`]
    /// holds the previous state), so the overlay doesn't flap near the threshold.
    srtt_showing: bool,
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
    /// mosh's prediction-epoch gate — the mechanism that keeps speculative echo
    /// from flashing in a context that doesn't echo keystrokes (e.g. vim normal
    /// mode, where `j` moves the cursor and is never printed). Every prediction
    /// is stamped with `prediction_epoch`; it is *tracked and validated* but
    /// **not displayed** until `confirmed_epoch` reaches its epoch — which only
    /// happens when a prediction in that epoch (or earlier) is confirmed correct
    /// by the server. So the very first keystroke in any fresh context is
    /// withheld until the server proves the context echoes; if it never does
    /// (vim normal mode), nothing is ever shown. [`Self::become_tentative`] bumps
    /// `prediction_epoch` on any unpredictable input (control byte, escape
    /// sequence, CR/LF, line wrap) so entering such a context re-arms the gate.
    /// Mirrors mosh's `prediction_epoch` / `confirmed_epoch` / `tentative_until_epoch`.
    prediction_epoch: u64,
    confirmed_epoch: u64,
    cols: u16,
    rows: u16,
    /// Rolling record of prediction outcomes for the client status bar, one entry
    /// per server confirmation: `(time_ms, correct, total)` where `total` is how
    /// many confirmed predictions that update carried and `correct` how many
    /// matched. Pruned to [`OUTCOME_WINDOW_MS`] in [`Self::new_server_screen`], so
    /// [`Self::accuracy`] reports recent accuracy rather than a lifetime average.
    outcomes: std::collections::VecDeque<(u64, u32, u32)>,
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
            cursor_epoch: 0,
            have_cursor: false,
            utf8: Vec::new(),
            suppress: false,
            esc: EscPhase::None,
            esc_params: Vec::new(),
            srtt_ms: 0.0,
            srtt_showing: false,
            flagging: true,
            resync_suppress: false,
            glitch_trigger: 0,
            last_quick_confirmation_ms: 0,
            confidence: 0,
            // Start one epoch ahead of "confirmed": the first prediction is
            // tentative until the server proves this context echoes (mosh's
            // `prediction_epoch(1)`, `confirmed_epoch(0)`).
            prediction_epoch: 1,
            confirmed_epoch: 0,
            cols: 0,
            rows: 0,
            outcomes: std::collections::VecDeque::new(),
        }
    }

    /// Begin a new prediction epoch (mosh's `become_tentative`): predictions
    /// made from now on are stamped one epoch higher and stay invisible until a
    /// confirmation proves this context echoes. Called on any input whose
    /// on-screen effect we can't safely predict (control byte, escape sequence,
    /// CR/LF, line wrap), so entering a non-echoing context re-arms the display
    /// gate even if the previous epoch was confirmed.
    fn become_tentative(&mut self) {
        self.prediction_epoch = self.prediction_epoch.saturating_add(1);
    }

    /// Update the SRTT estimate used by [`PredictMode::Adaptive`] gating, and
    /// re-evaluate the latched SRTT trigger with hysteresis: cross above HIGH to
    /// latch on, fall to/below LOW to latch off, hold state in between.
    pub fn set_srtt(&mut self, srtt_ms: f64) {
        self.srtt_ms = srtt_ms;
        if srtt_ms > ADAPTIVE_SRTT_TRIGGER_HIGH_MS {
            self.srtt_showing = true;
        } else if srtt_ms <= ADAPTIVE_SRTT_TRIGGER_LOW_MS {
            self.srtt_showing = false;
        }
    }

    /// Toggle underlining of tentative predictions (default on).
    pub fn set_flagging(&mut self, on: bool) {
        self.flagging = on;
    }

    /// Record one server update's prediction tally and prune outcomes older than
    /// [`OUTCOME_WINDOW_MS`], so [`Self::accuracy`] stays a recent-window meter.
    /// A zero-total update is skipped (nothing was confirmed to score).
    fn record_outcome(&mut self, now_ms: u64, correct: u32, total: u32) {
        if total > 0 {
            self.outcomes.push_back((now_ms, correct, total));
        }
        let cutoff = now_ms.saturating_sub(OUTCOME_WINDOW_MS);
        while let Some(&(t, _, _)) = self.outcomes.front() {
            if t < cutoff {
                self.outcomes.pop_front();
            } else {
                break;
            }
        }
    }

    /// Prediction accuracy over the recent window for the client status bar:
    /// `(total_confirmed, fraction_correct)`. `None` when no predictions have been
    /// confirmed in the window (nothing to report — the bar shows a dash).
    pub fn accuracy(&self, now_ms: u64) -> Option<(u32, f64)> {
        let cutoff = now_ms.saturating_sub(OUTCOME_WINDOW_MS);
        let (mut correct, mut total) = (0u64, 0u64);
        for &(t, c, n) in &self.outcomes {
            if t >= cutoff {
                correct += c as u64;
                total += n as u64;
            }
        }
        (total > 0).then(|| (total as u32, correct as f64 / total as f64))
    }

    /// Whether the speculative overlay is currently being displayed (predictions
    /// visible to the user), for the status bar's prediction status.
    pub fn is_showing(&self) -> bool {
        self.showing()
    }

    /// Whether predictions are currently flagged as glitchy (pending long enough
    /// that the link looks stalled), for the status bar.
    pub fn is_glitchy(&self) -> bool {
        self.glitch_trigger > 0
    }

    /// The configured prediction mode, for the status bar.
    pub fn mode(&self) -> PredictMode {
        self.mode
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
                self.srtt_showing
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
        // A flush starts a fresh, unconfirmed epoch: whatever we show next must
        // re-earn a confirmation before it displays (mosh's `reset` →
        // `become_tentative`).
        self.become_tentative();
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
            self.continue_escape(ch, input_index, base, now_ms);
            return;
        }
        if self.suppress {
            return; // inside an unpredictable (escape) sequence
        }
        match ch {
            // Carriage return: go to column 0. Unpredictable enough (the shell
            // may echo a newline, run a command, repaint) that mosh starts a
            // fresh epoch — so the first keystroke of the next line is withheld
            // until it's confirmed.
            '\r' => {
                self.become_tentative();
                self.cursor_col = 0;
                self.cursor_index = input_index;
                self.cursor_at_ms = now_ms;
                self.cursor_epoch = self.prediction_epoch;
            }
            // Line feed: next row (predicting scroll is unsafe, so clamp). Like
            // CR, an unpredictable boundary → fresh epoch.
            '\n' => {
                self.become_tentative();
                self.cursor_col = 0;
                if self.cursor_row + 1 < self.rows {
                    self.cursor_row += 1;
                }
                self.cursor_index = input_index;
                self.cursor_at_ms = now_ms;
                self.cursor_epoch = self.prediction_epoch;
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
                self.cursor_epoch = self.prediction_epoch;
            }
            // Tab: advance to the next multiple of 8. The server may render tab
            // stops differently, so mosh treats it as unpredictable → fresh epoch.
            '\t' => {
                self.become_tentative();
                let next = ((self.cursor_col / 8) + 1) * 8;
                self.cursor_col = next.min(self.cols - 1);
                self.cursor_index = input_index;
                self.cursor_at_ms = now_ms;
                self.cursor_epoch = self.prediction_epoch;
            }
            // Ctrl-A / Ctrl-E: readline beginning-/end-of-line. Pure cursor moves,
            // gated by the epoch like the arrow keys — if this context doesn't bind
            // them this way (an app that grabs Ctrl-A), the prediction is
            // contradicted by the server and dropped without ever displaying.
            '\u{1}' => {
                self.predict_cursor_to(0, input_index, now_ms);
            }
            '\u{5}' => {
                let e = self.line_end_col(self.cursor_row, base);
                self.predict_cursor_to(e, input_index, now_ms);
            }
            // Escape: begin an escape sequence — it may be a cursor motion we can
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
                self.cursor_epoch = self.prediction_epoch;
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
            epoch: self.prediction_epoch,
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

    /// Continue parsing an input escape sequence, predicting the cursor-only
    /// motions — arrows, Home/End, and word-wise jumps (`M-b`/`M-f`, Ctrl-arrow)
    /// — and abandoning prediction for anything else (we can't safely predict
    /// arbitrary escape effects). Every motion is stamped in the current epoch,
    /// so the gate withholds it until the context is confirmed to echo it.
    fn continue_escape(&mut self, ch: char, input_index: u64, base: &Screen, now_ms: u64) {
        match self.esc {
            EscPhase::Esc => match ch {
                '[' => {
                    self.esc = EscPhase::Csi;
                    self.esc_params.clear();
                }
                'O' => self.esc = EscPhase::Ss3,
                // Meta (Alt) word motions are default readline bindings:
                // `ESC b` = backward-word, `ESC f` = forward-word.
                'b' => {
                    self.esc = EscPhase::None;
                    let c = self.word_left(self.cursor_row, base);
                    self.predict_cursor_to(c, input_index, now_ms);
                }
                'f' => {
                    self.esc = EscPhase::None;
                    let c = self.word_right(self.cursor_row, base);
                    self.predict_cursor_to(c, input_index, now_ms);
                }
                _ => self.abandon_escape(),
            },
            EscPhase::Ss3 => {
                self.esc = EscPhase::None;
                match ch {
                    'C' => self.predict_cursor_h(true, input_index, now_ms), // right
                    'D' => self.predict_cursor_h(false, input_index, now_ms), // left
                    'H' => self.predict_cursor_to(0, input_index, now_ms),   // Home
                    'F' => {
                        let e = self.line_end_col(self.cursor_row, base); // End
                        self.predict_cursor_to(e, input_index, now_ms);
                    }
                    _ => self.abandon_escape(),
                }
            }
            EscPhase::Csi => {
                // Accumulate parameter bytes (digits / `;`) until the final byte.
                if ch.is_ascii_digit() || ch == ';' {
                    if self.esc_params.len() < 16 {
                        self.esc_params.push(ch as u8);
                    }
                    return; // stay in CSI
                }
                self.esc = EscPhase::None;
                // A modifier param (e.g. `1;5` Ctrl, `1;3` Alt) turns the arrow
                // finals C/D into word motions, matching the usual inputrc
                // bindings; a bare or `1` param is a single-column arrow.
                let modified = self.esc_has_modifier();
                match ch {
                    'C' if modified => {
                        let c = self.word_right(self.cursor_row, base);
                        self.predict_cursor_to(c, input_index, now_ms);
                    }
                    'D' if modified => {
                        let c = self.word_left(self.cursor_row, base);
                        self.predict_cursor_to(c, input_index, now_ms);
                    }
                    'C' => self.predict_cursor_h(true, input_index, now_ms), // right
                    'D' => self.predict_cursor_h(false, input_index, now_ms), // left
                    'H' => self.predict_cursor_to(0, input_index, now_ms),   // Home
                    'F' => {
                        let e = self.line_end_col(self.cursor_row, base); // End
                        self.predict_cursor_to(e, input_index, now_ms);
                    }
                    // `ESC [ n ~` variants: 1/7 = Home, 4/8 = End.
                    '~' => match self.esc_leading_param() {
                        1 | 7 => self.predict_cursor_to(0, input_index, now_ms),
                        4 | 8 => {
                            let e = self.line_end_col(self.cursor_row, base);
                            self.predict_cursor_to(e, input_index, now_ms);
                        }
                        _ => self.abandon_escape(),
                    },
                    _ => self.abandon_escape(),
                }
            }
            // Only reached with esc != None (guarded by the caller).
            EscPhase::None => {}
        }
    }

    /// Abandon the in-progress escape sequence: flush speculation and suppress
    /// prediction for the rest of this input batch.
    fn abandon_escape(&mut self) {
        self.esc = EscPhase::None;
        self.reset();
        self.suppress = true;
    }

    /// The second (modifier) CSI parameter is present and > 1 — i.e. the key was
    /// pressed with Ctrl/Alt/Shift (`1;5C` etc.), marking a word-wise arrow.
    fn esc_has_modifier(&self) -> bool {
        let s = std::str::from_utf8(&self.esc_params).unwrap_or("");
        s.split(';')
            .nth(1)
            .and_then(|m| m.parse::<u32>().ok())
            .is_some_and(|m| m >= 2)
    }

    /// The leading CSI parameter as a number (0 if absent/unparseable), used to
    /// classify the `ESC [ n ~` family.
    fn esc_leading_param(&self) -> u32 {
        let s = std::str::from_utf8(&self.esc_params).unwrap_or("");
        s.split(';')
            .next()
            .and_then(|m| m.parse::<u32>().ok())
            .unwrap_or(0)
    }

    /// Predict a one-column cursor move (right if `right`, else left), clamped to
    /// the screen — no cell changes.
    fn predict_cursor_h(&mut self, right: bool, input_index: u64, now_ms: u64) {
        let col = if right {
            self.cursor_col + 1
        } else {
            self.cursor_col.saturating_sub(1)
        };
        self.predict_cursor_to(col, input_index, now_ms);
    }

    /// Predict an absolute cursor column on the current row (clamped to the
    /// screen), with no cell changes. Stamped in the current prediction epoch
    /// like the arrow keys, so the epoch gate withholds it until this context is
    /// confirmed to echo cursor moves.
    fn predict_cursor_to(&mut self, col: u16, input_index: u64, now_ms: u64) {
        self.cursor_col = col.min(self.cols.saturating_sub(1));
        self.cursor_index = input_index;
        self.cursor_at_ms = now_ms;
        self.cursor_epoch = self.prediction_epoch;
    }

    /// The end-of-line cursor column for `row`: one past the rightmost non-blank
    /// cell (readline's end-of-line / `Ctrl-E`), or column 0 on a blank row.
    /// [`Self::predict_cursor_to`] clamps it to the screen width.
    fn line_end_col(&self, row: u16, base: &Screen) -> u16 {
        self.line_content_end(row, base).map_or(0, |e| e + 1)
    }

    /// Predicted column after a readline `backward-word` (`M-b`) from the cursor:
    /// skip delimiters left, then the word's characters, landing at its start.
    fn word_left(&self, row: u16, base: &Screen) -> u16 {
        let mut i = self.cursor_col;
        while i > 0 && !is_word_char(self.displayed_cell(row, i - 1, base).c) {
            i -= 1;
        }
        while i > 0 && is_word_char(self.displayed_cell(row, i - 1, base).c) {
            i -= 1;
        }
        i
    }

    /// Predicted column after a readline `forward-word` (`M-f`) from the cursor:
    /// skip delimiters right, then the word's characters, landing just past its
    /// end. Bounded by the line's content extent so it can't run off into blanks.
    fn word_right(&self, row: u16, base: &Screen) -> u16 {
        let end = self.line_end_col(row, base);
        let mut i = self.cursor_col;
        while i < end && !is_word_char(self.displayed_cell(row, i, base).c) {
            i += 1;
        }
        while i < end && is_word_char(self.displayed_cell(row, i, base).c) {
            i += 1;
        }
        i
    }

    fn advance_cursor(&mut self) {
        if self.cursor_col + 1 < self.cols {
            self.cursor_col += 1;
        } else {
            // Wrap. mosh's "tricky last column": the server may wrap or may
            // overwrite, so start a fresh epoch and let the wrapped prediction
            // re-earn display.
            self.become_tentative();
            self.cursor_col = 0;
            if self.cursor_row + 1 < self.rows {
                self.cursor_row += 1;
            }
        }
    }

    /// Incorporate a freshly received server screen received at `now_ms`:
    /// validate predictions the server has now applied (`input_index <=
    /// screen.echo_ack`, mosh's `late_ack`), promote the confirmed epoch from
    /// the ones that came back correct, and cull. A *visible* (confirmed-epoch)
    /// misprediction flushes the whole overlay; a *tentative* (never-displayed)
    /// one is killed quietly — nothing was on screen to correct.
    pub fn new_server_screen(&mut self, screen: &Screen, now_ms: u64) {
        if self.mode == PredictMode::Never {
            self.reset();
            return;
        }
        let ack = screen.echo_ack;
        // `confirmed_epoch` as it stood when these predictions were painted —
        // used to decide whether a now-confirmed prediction had actually been
        // displayed (mature, `epoch <= prev_confirmed`) or was still tentative.
        let prev_confirmed = self.confirmed_epoch;

        // Classify every *confirmed* prediction (the server has applied this
        // input) as correct or mispredicted; for mispredictions, whether the
        // prediction was mature enough to have been on screen.
        let mut visible_mispredict = false;
        let mut tentative_mispredict = false;
        let mut max_correct_epoch = prev_confirmed;
        // Tally this update's confirmed cell predictions for the status-bar
        // accuracy meter (cursor moves are excluded — a cell glyph is the
        // outcome the user actually reads).
        let mut n_correct: u32 = 0;
        let mut n_total: u32 = 0;
        for p in &self.cells {
            if p.input_index > ack {
                continue;
            }
            let correct = screen
                .cell(p.row, p.col)
                .map(|actual| actual.c == p.cell.c)
                .unwrap_or(false);
            n_total += 1;
            if correct {
                n_correct += 1;
                max_correct_epoch = max_correct_epoch.max(p.epoch);
            } else if p.epoch <= prev_confirmed {
                visible_mispredict = true;
            } else {
                tentative_mispredict = true;
            }
        }
        self.record_outcome(now_ms, n_correct, n_total);
        // The cursor prediction, same treatment (mosh's
        // `ConditionalCursorMove::get_validity` → `IncorrectOrExpired`).
        if self.have_cursor && self.cursor_index <= ack {
            let cursor_correct =
                screen.cursor_row == self.cursor_row && screen.cursor_col == self.cursor_col;
            if cursor_correct {
                max_correct_epoch = max_correct_epoch.max(self.cursor_epoch);
            } else if self.cursor_epoch <= prev_confirmed {
                visible_mispredict = true;
            } else {
                tentative_mispredict = true;
            }
        }

        // A *visible* prediction the server contradicted means the user actually
        // saw the wrong thing: flush the whole overlay to the truth and start a
        // fresh (tentative) epoch — mosh's `cull` for a non-tentative
        // `IncorrectOrExpired`.
        if visible_mispredict {
            self.reset(); // clears the overlay AND bumps to a fresh epoch
            self.resync_suppress = true; // suppress overlay until the next clean update
            self.confidence = 0; // track record broken — re-earn confidence
            return;
        }

        // No visible miss: promote the confirmed epoch from the correct
        // confirmations, so subsequent predictions in those epochs display.
        self.confirmed_epoch = max_correct_epoch;

        // A tentative (never-displayed) prediction was wrong — e.g. vim
        // swallowed the keystroke as a motion instead of echoing it. Nothing was
        // on screen, so there is nothing to flush: quietly drop every
        // still-unconfirmed prediction (those in an epoch the server hasn't
        // confirmed) and bump to a fresh epoch (mosh's `kill_epoch`). The epoch
        // never advances, so the speculative glyph is never shown — this is what
        // stops `jjjj` from flashing in vim normal mode.
        if tentative_mispredict {
            self.cells.retain(|p| p.epoch <= self.confirmed_epoch);
            if self.cursor_epoch > self.confirmed_epoch {
                self.have_cursor = false;
            }
            self.become_tentative();
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
        let quick_confirm = self.cells.iter().any(|p| {
            p.input_index <= ack && now_ms.saturating_sub(p.predicted_at_ms) < GLITCH_THRESHOLD_MS
        });
        if quick_confirm
            && self.glitch_trigger > 0
            && now_ms.saturating_sub(GLITCH_REPAIR_MININTERVAL_MS)
                >= self.last_quick_confirmation_ms
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
            // Only paint predictions in a *confirmed* epoch (mosh's
            // `ConditionalOverlay::tentative` gate): an unconfirmed-epoch
            // prediction is tracked and validated but never shown, so a glyph
            // the server won't echo (vim normal-mode `j`) never flashes.
            if p.input_index > server.echo_ack && p.epoch <= self.confirmed_epoch {
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
            && self.cursor_epoch <= self.confirmed_epoch
            && self.cursor_row < s.rows
            && self.cursor_col < s.cols
        {
            s.cursor_row = self.cursor_row;
            s.cursor_col = self.cursor_col;
        }
        s
    }

    /// The current prediction / confirmed epoch (test/observability). Predictions
    /// stamped at or below `confirmed_epoch` are displayed; those above it are
    /// still tentative (see the field docs).
    #[cfg(test)]
    fn prediction_epoch(&self) -> u64 {
        self.prediction_epoch
    }
    #[cfg(test)]
    fn confirmed_epoch(&self) -> u64 {
        self.confirmed_epoch
    }
    /// Test helper: pretend the current epoch is already confirmed, so a freshly
    /// made prediction in it displays without first round-tripping a server
    /// confirmation. Used by the display-logic tests that aren't about the
    /// "earn the first echo" gate itself.
    #[cfg(test)]
    fn prime_epoch(&mut self) {
        self.confirmed_epoch = self.prediction_epoch;
    }

    /// Number of currently-active (unconfirmed) cell predictions.
    pub fn active_predictions(&self) -> usize {
        self.cells.len()
    }

    /// Whether the input event at `idx` (a `UserStream::total()` value) is being
    /// *displayed right now* as predictive local echo — i.e. predictions are
    /// showing and this keystroke contributed a visible cell or a cursor move.
    /// Used by the client's perf recorder to tell a locally-echoed keystroke
    /// (response ≈ 0) from one still waiting on the server. Because a keystroke is
    /// only registered just before this is queried, the server has not yet acked
    /// it (`echo_ack < idx`), so any prediction tagged with `idx` is necessarily
    /// overlaid by [`Self::predicted_screen`] when [`Self::showing`] holds.
    pub fn displaying_input(&self, idx: u64) -> bool {
        self.showing()
            && (self.cells.iter().any(|p| p.input_index == idx)
                || (self.have_cursor && self.cursor_index == idx))
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
    fn accuracy_tracks_recent_outcomes() {
        let mut p = PredictionEngine::new(PredictMode::Always);
        p.prime_epoch(); // established context, so predictions are visible
        assert_eq!(p.accuracy(0), None, "nothing confirmed yet → no meter");

        // Type 'x'; the server confirms it correctly at (0,0).
        let base = screen_with_ack(20, 2, 0);
        p.new_user_bytes(b"x", &base, 1, 0);
        let mut good = confirmed_screen(20, 2, 1, 1);
        good.cells[0].c = 'x';
        p.new_server_screen(&good, 10);
        assert_eq!(p.accuracy(10), Some((1, 1.0)), "one correct → 100%");

        // Type 'y' (predicted at the new cursor col 1); the server contradicts it.
        p.new_user_bytes(b"y", &good, 2, 20);
        let mut bad = confirmed_screen(20, 2, 2, 1);
        bad.cells[0].c = 'x'; // the already-confirmed glyph stays
        bad.cells[1].c = 'Z'; // but 'y' was mispredicted here
        p.new_server_screen(&bad, 30);
        assert_eq!(p.accuracy(30), Some((2, 0.5)), "one of two correct → 50%");

        // Both samples age out of the one-minute window.
        assert_eq!(
            p.accuracy(30 + 60_001),
            None,
            "old outcomes drop from the window"
        );
    }

    #[test]
    fn displaying_input_tracks_shown_keystrokes() {
        // Always mode: a freshly typed key at input index 2 is displayed locally.
        let mut p = PredictionEngine::new(PredictMode::Always);
        let base = screen_with_ack(20, 3, 0);
        p.new_user_bytes(b"hi", &base, 2, 0);
        assert!(
            p.displaying_input(2),
            "the typed keystroke is locally echoed"
        );
        assert!(
            !p.displaying_input(99),
            "an unrelated index is not displayed"
        );

        // Adaptive mode below the SRTT trigger: predictions tracked but not shown,
        // so the keystroke is *not* counted as locally displayed.
        let mut p = PredictionEngine::new(PredictMode::Adaptive);
        p.set_srtt(5.0);
        p.new_user_bytes(b"x", &base, 1, 0);
        assert!(!p.displaying_input(1), "hidden prediction is not displayed");
        p.set_srtt(120.0); // laggy link → now shown
        assert!(p.displaying_input(1), "shown once the link is laggy");
    }

    #[test]
    fn predicts_typed_char_immediately() {
        let mut p = PredictionEngine::new(PredictMode::Always);
        p.prime_epoch();
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
        p.prime_epoch();
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
        p.prime_epoch(); // an established, displaying context, so the miss is visible
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
        p.prime_epoch(); // an established, displaying context, so the miss is visible
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
        p.prime_epoch();
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
        p.prime_epoch();
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
    fn adaptive_srtt_trigger_has_hysteresis() {
        let mut p = PredictionEngine::new(PredictMode::Adaptive);
        p.prime_epoch();
        let base = screen_with_ack(20, 2, 0);
        p.new_user_bytes(b"x", &base, 1, 0);
        let shown = |p: &PredictionEngine| p.predicted_screen(&base).cell(0, 0).unwrap().c == 'x';

        // Starts off; below LOW stays off.
        p.set_srtt(10.0);
        assert!(!shown(&p));
        // In the band (LOW, HIGH] while off → still off (no premature flip).
        p.set_srtt(25.0);
        assert!(!shown(&p), "band must not turn the overlay on from off");
        // Above HIGH → latch on.
        p.set_srtt(35.0);
        assert!(shown(&p));
        // Back into the band while on → stays on (no flap).
        p.set_srtt(25.0);
        assert!(shown(&p), "band must hold the overlay on once latched");
        // At/below LOW → latch off.
        p.set_srtt(20.0);
        assert!(!shown(&p));
    }

    #[test]
    fn tentative_predictions_are_underlined() {
        let mut p = PredictionEngine::new(PredictMode::Always);
        p.prime_epoch();
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
        p.prime_epoch(); // an established, displaying context, so the miss is visible
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
        p.prime_epoch();
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
        p.prime_epoch();
        let base = screen_with_ack(20, 3, 0);
        p.new_user_bytes(b"abc", &base, 3, 0);
        assert_eq!(p.predicted_screen(&base).cursor_col, 3);

        // Left arrow (CSI form): cursor moves left, overlay kept.
        p.new_user_bytes(b"\x1b[D", &base, 4, 0);
        let shown = p.predicted_screen(&base);
        assert_eq!(shown.cursor_col, 2, "left arrow moved the cursor");
        assert_eq!(
            shown.cell(0, 0).unwrap().c,
            'a',
            "typed glyphs survive the arrow"
        );

        // Right arrow (SS3 / application-cursor-keys form): back to col 3.
        p.new_user_bytes(b"\x1bOC", &base, 5, 0);
        assert_eq!(
            p.predicted_screen(&base).cursor_col,
            3,
            "right arrow moved the cursor"
        );
    }

    /// Ctrl-A / Ctrl-E and the Home/End keys (CSI, SS3, and `ESC [ n ~` forms)
    /// are predicted as beginning-/end-of-line cursor jumps.
    #[test]
    fn predicts_line_home_end() {
        let mut p = PredictionEngine::new(PredictMode::Always);
        p.prime_epoch();
        let base = screen_with_ack(20, 3, 0);
        p.new_user_bytes(b"abc", &base, 3, 0);
        assert_eq!(p.predicted_screen(&base).cursor_col, 3);

        // Ctrl-A → beginning of line.
        p.new_user_bytes(b"\x01", &base, 4, 0);
        assert_eq!(p.predicted_screen(&base).cursor_col, 0, "Ctrl-A → col 0");
        // Ctrl-E → end of line (one past the last glyph 'c').
        p.new_user_bytes(b"\x05", &base, 5, 0);
        assert_eq!(p.predicted_screen(&base).cursor_col, 3, "Ctrl-E → line end");

        // Home key, CSI form (ESC [ H) and ESC [ 1 ~.
        p.new_user_bytes(b"\x1b[H", &base, 6, 0);
        assert_eq!(p.predicted_screen(&base).cursor_col, 0, "CSI Home");
        p.new_user_bytes(b"\x1b[4~", &base, 7, 0);
        assert_eq!(p.predicted_screen(&base).cursor_col, 3, "CSI End (ESC[4~)");
        // SS3 Home (ESC O H).
        p.new_user_bytes(b"\x1bOH", &base, 8, 0);
        assert_eq!(p.predicted_screen(&base).cursor_col, 0, "SS3 Home");
    }

    /// Word-wise motions: `M-b` / `M-f` (default readline) and Ctrl-arrow
    /// (`ESC [ 1 ; 5 D/C`) jump over whole alphanumeric words.
    #[test]
    fn predicts_word_motions() {
        let mut p = PredictionEngine::new(PredictMode::Always);
        p.prime_epoch();
        let base = screen_with_ack(20, 3, 0);
        p.new_user_bytes(b"foo bar", &base, 7, 0); // cursor at col 7 (end)
        assert_eq!(p.predicted_screen(&base).cursor_col, 7);

        // M-b: back to the start of "bar".
        p.new_user_bytes(b"\x1bb", &base, 8, 0);
        assert_eq!(
            p.predicted_screen(&base).cursor_col,
            4,
            "M-b → start of bar"
        );
        // M-b again: back to the start of "foo".
        p.new_user_bytes(b"\x1bb", &base, 9, 0);
        assert_eq!(
            p.predicted_screen(&base).cursor_col,
            0,
            "M-b → start of foo"
        );
        // M-f: forward to the end of "foo".
        p.new_user_bytes(b"\x1bf", &base, 10, 0);
        assert_eq!(p.predicted_screen(&base).cursor_col, 3, "M-f → end of foo");
        // Ctrl-Right (ESC[1;5C): forward to the end of "bar".
        p.new_user_bytes(b"\x1b[1;5C", &base, 11, 0);
        assert_eq!(
            p.predicted_screen(&base).cursor_col,
            7,
            "Ctrl-Right → end of bar"
        );
        // Ctrl-Left (ESC[1;5D): back to the start of "bar".
        p.new_user_bytes(b"\x1b[1;5D", &base, 12, 0);
        assert_eq!(
            p.predicted_screen(&base).cursor_col,
            4,
            "Ctrl-Left → start of bar"
        );
    }

    /// A motion the server contradicts is dropped by the epoch gate without
    /// corrupting any glyphs (the cursor-only motions never touch cells).
    #[test]
    fn mispredicted_motion_does_not_corrupt_cells() {
        let mut p = PredictionEngine::new(PredictMode::Always);
        p.prime_epoch();
        let base = screen_with_ack(20, 3, 0);
        p.new_user_bytes(b"abc", &base, 3, 0);
        // Ctrl-A predicts col 0, but the server (some app that rebinds it) leaves
        // the cursor at col 3 and the glyphs intact.
        p.new_user_bytes(b"\x01", &base, 4, 0);
        let mut confirmed = screen_with_ack(20, 3, 4);
        confirmed.cursor_col = 3;
        for (i, c) in "abc".chars().enumerate() {
            confirmed.cells[i].c = c;
        }
        p.new_server_screen(&confirmed, 0);
        let shown = p.predicted_screen(&confirmed);
        assert_eq!(shown.cursor_col, 3, "cursor resyncs to the server");
        assert_eq!(
            shown.cell(0, 0).unwrap().c,
            'a',
            "glyphs untouched by the bad motion"
        );
    }

    /// Typing in the *middle* of a line is predicted as an insert that shifts the
    /// rest of the line right (shells' default readline insert mode), not an
    /// overwrite.
    #[test]
    fn predicts_insert_shift_mid_line() {
        let mut p = PredictionEngine::new(PredictMode::Always);
        p.prime_epoch();
        let mut base = screen_with_ack(20, 2, 0);
        base.cells[0].c = 'X';
        base.cells[1].c = 'Y';
        base.cells[2].c = 'Z';
        base.cursor_col = 1; // between X and Y

        p.new_user_bytes(b"a", &base, 1, 0);
        let shown = p.predicted_screen(&base);
        assert_eq!(
            shown.cell(0, 0).unwrap().c,
            'X',
            "before the cursor: unchanged"
        );
        assert_eq!(
            shown.cell(0, 1).unwrap().c,
            'a',
            "glyph inserted at the cursor"
        );
        assert_eq!(
            shown.cell(0, 2).unwrap().c,
            'Y',
            "rest of the line shifted right"
        );
        assert_eq!(shown.cell(0, 3).unwrap().c, 'Z', "…and Z too");
        assert_eq!(shown.cursor_col, 2, "cursor advanced past the insert");
    }

    /// Typing at the end of a line stays a single-cell overwrite (no spurious
    /// whole-row shift), so the common case is cheap and never mispredicts.
    #[test]
    fn end_of_line_typing_does_not_shift() {
        let mut p = PredictionEngine::new(PredictMode::Always);
        p.prime_epoch();
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
        p.prime_epoch();
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
        p.prime_epoch();
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

    // ---- mosh's prediction-epoch gate (the vim-normal-mode fix) ----

    /// The core of the fix: a prediction made in an unconfirmed epoch is tracked
    /// and validated but NOT displayed. On a fresh engine nothing has been
    /// confirmed, so the first predicted glyph is withheld until the server
    /// proves this context echoes keystrokes — even in `Always` mode.
    #[test]
    fn unconfirmed_epoch_prediction_is_withheld() {
        let mut p = PredictionEngine::new(PredictMode::Always);
        let base = screen_with_ack(20, 3, 0);
        p.new_user_bytes(b"j", &base, 1, 0);
        assert_eq!(p.active_predictions(), 1, "prediction is tracked");
        assert_eq!(
            p.predicted_screen(&base).cell(0, 0).unwrap().c,
            ' ',
            "but not displayed until its epoch is confirmed"
        );
        assert_eq!(p.confirmed_epoch(), 0, "nothing confirmed yet");
    }

    /// vim normal mode: `hjkl` move the cursor and are never echoed, so the
    /// epoch never confirms — and the predicted glyphs are never shown, however
    /// many keys are pressed. This is the `jjjjj`-flashing bug this fix removes.
    #[test]
    fn vim_normal_mode_motion_keys_never_flash() {
        let mut p = PredictionEngine::new(PredictMode::Always);
        // A server screen whose first cell holds a `~` (an empty vim line); the
        // cursor parks at the origin and never tracks our right-moving guess.
        let mut server = screen_with_ack(20, 5, 0);
        server.cells[0].c = '~';

        for i in 1..=5u64 {
            p.new_user_bytes(b"j", &server, i, i * 10);
            assert_eq!(
                p.predicted_screen(&server).cell(0, 0).unwrap().c,
                '~',
                "motion key must not paint a glyph (iteration {i})"
            );
            // The server applies the input but echoes nothing new: the cell is
            // unchanged and the cursor did not move where we guessed.
            let mut next = server.clone();
            next.echo_ack = i;
            next.cursor_row = 0;
            next.cursor_col = 0;
            p.new_server_screen(&next, i * 10 + 5);
            assert_eq!(
                p.confirmed_epoch(),
                0,
                "epoch never confirms in a non-echoing context (iteration {i})"
            );
        }
    }

    /// Once a prediction is confirmed correct (a context that *does* echo — a
    /// shell prompt, vim insert mode), the epoch is promoted and subsequent
    /// predictions in it display immediately. (The first keystroke is still
    /// withheld; that's the price of learning the context echoes.)
    #[test]
    fn confirmed_epoch_enables_subsequent_predictions() {
        let mut p = PredictionEngine::new(PredictMode::Always);
        let base = screen_with_ack(20, 3, 0);

        // First keystroke: withheld (unconfirmed epoch).
        p.new_user_bytes(b"a", &base, 1, 0);
        assert_eq!(p.predicted_screen(&base).cell(0, 0).unwrap().c, ' ');

        // Server echoes it at (0,0) with the cursor advanced → epoch confirmed.
        let mut confirmed = confirmed_screen(20, 3, 1, 1);
        confirmed.cells[0].c = 'a';
        p.new_server_screen(&confirmed, 10);
        assert_eq!(
            p.confirmed_epoch(),
            p.prediction_epoch(),
            "the correct confirmation promoted the epoch"
        );

        // The next keystroke in that now-confirmed epoch displays right away.
        p.new_user_bytes(b"b", &confirmed, 2, 20);
        assert_eq!(
            p.predicted_screen(&confirmed).cell(0, 1).unwrap().c,
            'b',
            "a prediction in a confirmed epoch shows immediately"
        );
    }

    /// An unpredictable byte (here an unhandled escape sequence) starts a fresh
    /// tentative epoch, so the keystroke after it is withheld again — even
    /// though the prior epoch was confirmed. This is what re-arms the gate when
    /// you enter a non-echoing mode mid-session (e.g. launch vim from the shell).
    #[test]
    fn unpredictable_input_rearms_the_gate() {
        let mut p = PredictionEngine::new(PredictMode::Always);
        p.prime_epoch(); // already in a confirmed, predicting context
        let base = screen_with_ack(20, 3, 0);
        p.new_user_bytes(b"a", &base, 1, 0);
        assert_eq!(
            p.predicted_screen(&base).cell(0, 0).unwrap().c,
            'a',
            "confirmed-context prediction shows"
        );

        let before = p.prediction_epoch();
        // CSI Z (not an arrow we predict) → become_tentative + flush.
        p.new_user_bytes(b"\x1b[Z", &base, 2, 10);
        assert!(p.prediction_epoch() > before, "epoch bumped past confirmed");

        // A glyph typed now is in the new, unconfirmed epoch → withheld.
        p.new_user_bytes(b"b", &base, 3, 20);
        let shown = p.predicted_screen(&base);
        assert!(
            shown.cells.iter().all(|c| c.c != 'b'),
            "post-escape glyph withheld until the new epoch confirms"
        );
    }

    /// A tentative (never-displayed) misprediction is killed quietly: it does
    /// NOT flush the overlay or set the resync suppression the way a *visible*
    /// misprediction does — there was nothing on screen to correct.
    #[test]
    fn tentative_mispredict_is_quiet() {
        let mut p = PredictionEngine::new(PredictMode::Always);
        let base = screen_with_ack(20, 3, 0);
        // Unconfirmed epoch: this 'x' is tracked but never shown.
        p.new_user_bytes(b"x", &base, 1, 0);
        // Server applied input 1 but shows nothing there (cell stays blank) →
        // tentative misprediction.
        let mut applied = screen_with_ack(20, 3, 1);
        applied.cursor_col = 0;
        p.new_server_screen(&applied, 10);

        assert_eq!(
            p.active_predictions(),
            0,
            "the bad tentative cell is dropped"
        );
        assert_eq!(p.confirmed_epoch(), 0, "epoch stays unconfirmed");
        // A fresh prediction is still immediately representable (not stuck behind
        // a resync suppression that a visible miss would have set): it's just
        // withheld by the epoch gate, and the screen shows the truth.
        assert_eq!(
            p.predicted_screen(&applied).cell(0, 0).unwrap().c,
            ' ',
            "screen shows the server truth, no flicker"
        );
    }
}
