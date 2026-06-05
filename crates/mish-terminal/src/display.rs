//! Minimal screen-diff renderer — a Rust port of mosh's `Display::new_frame`
//! (`terminal/terminaldisplay.cc`).
//!
//! Given two [`Screen`] framebuffers, [`new_frame`] emits the minimal stream of
//! terminal escape sequences that turns `old` into `new`: cell-level change
//! detection, runs of blanks erased with ECH/EL, SGR only when the rendition
//! changes, and cursor moves optimized to CR/LF/BS where possible. This is both
//! mosh's wire diff (server→client) and the sequence the client paints to the
//! real TTY.
//!
//! Faithfulness is verified by *round-trip*: feeding `new_frame(old, new)` to an
//! emulator showing `old` reproduces `new` exactly (see the property tests and
//! [`crate::screen`]'s `apply_diff`). Bandwidth optimizations — vertical-scroll
//! detection (whole-screen and DECSTBM sub-regions, both directions), minimal
//! SGR deltas, ECH/EL blank runs — are all guarded by that round-trip identity:
//! a wrong optimization would change the reconstructed screen and fail the tests.

use crate::screen::{
    Cell, Color, Hyperlink, Screen, F_BOLD, F_DIM, F_HIDDEN, F_INVERSE, F_ITALIC, F_STRIKEOUT,
    F_UNDERLINE, NAMED_BACKGROUND, NAMED_FOREGROUND,
};

/// Builder that accumulates the output frame and tracks the emulated cursor /
/// rendition so it can optimize moves and SGR emission.
struct FrameState {
    out: Vec<u8>,
    /// Current cursor position; `-1` means "unknown" (force explicit move).
    cursor_x: i32,
    cursor_y: i32,
    cursor_visible: bool,
    /// Current pen `(fg, bg, flags)`. `None` means unknown — the first write
    /// then always emits an SGR to establish a known rendition, so an
    /// incremental frame is correct regardless of the pen the previous frame
    /// left behind.
    current: Option<(Color, Color, u16)>,
    /// Current OSC 8 hyperlink (outer `None` = unknown / not yet established).
    current_link: Option<Option<Hyperlink>>,
}

fn cell_width(cell: &Cell) -> i32 {
    // Geometry derives from the character's display width, not a stored flag.
    use unicode_width::UnicodeWidthChar;
    if UnicodeWidthChar::width(cell.c).unwrap_or(1) == 2 {
        2
    } else {
        1
    }
}

/// A cell that can be reproduced by an erase (ECH/EL). Terminal erase fills with
/// only the current background (BCE) — foreground and attributes are reset — so
/// a space is "erasable" only when its fg is the default and it has no flags.
/// Its background may be anything. Spaces with a colored fg or attributes must
/// be drawn as real characters to preserve their rendition.
fn is_blank(cell: &Cell) -> bool {
    cell.c == ' '
        && cell.flags == 0
        && cell.combining.is_empty()
        && cell.hyperlink.is_none()
        && cell.fg == Color::Named(NAMED_FOREGROUND)
}

impl FrameState {
    fn new(old: &Screen) -> Self {
        Self {
            out: Vec::with_capacity(old.cols as usize * old.rows as usize),
            cursor_x: old.cursor_col as i32,
            cursor_y: old.cursor_row as i32,
            cursor_visible: old.cursor_visible,
            current: None,
            current_link: None,
        }
    }

    /// Emit an OSC 8 open/close if the target hyperlink differs from current.
    fn update_hyperlink(&mut self, link: &Option<Hyperlink>) {
        if self.current_link.as_ref() == Some(link) {
            return;
        }
        self.current_link = Some(link.clone());
        match link {
            Some(h) => {
                let params = match &h.id {
                    Some(id) => format!("id={id}"),
                    None => String::new(),
                };
                self.push(&format!("\x1b]8;{};{}\x1b\\", params, h.uri));
            }
            None => self.push("\x1b]8;;\x1b\\"),
        }
    }

    fn push(&mut self, s: &str) {
        self.out.extend_from_slice(s.as_bytes());
    }

    fn push_n(&mut self, n: usize, b: u8) {
        self.out.extend(std::iter::repeat_n(b, n));
    }

    /// Move the cursor, optimizing to CR/LF/BS when cheap, like mosh.
    fn append_move(&mut self, y: i32, x: i32) {
        let last_x = self.cursor_x;
        let last_y = self.cursor_y;
        self.cursor_x = x;
        self.cursor_y = y;
        if last_x != -1 && last_y != -1 {
            // CR + LFs for a move to column 0 a few rows down.
            if x == 0 && (0..5).contains(&(y - last_y)) {
                if last_x != 0 {
                    self.out.push(b'\r');
                }
                self.push_n((y - last_y) as usize, b'\n');
                return;
            }
            // Backspaces for a short leftward move on the same row.
            if y == last_y && x < last_x && (last_x - x) < 5 {
                self.push_n((last_x - x) as usize, 0x08);
                return;
            }
        }
        self.push(&format!("\x1b[{};{}H", y + 1, x + 1));
    }

    /// Hide the cursor before a "silent" reposition, then move.
    fn append_silent_move(&mut self, y: i32, x: i32) {
        if self.cursor_x == x && self.cursor_y == y {
            return;
        }
        if self.cursor_visible {
            self.push("\x1b[?25l");
            self.cursor_visible = false;
        }
        self.append_move(y, x);
    }

    /// Emit an SGR sequence if the target rendition differs from current (or is
    /// not yet established). When only the colors changed (attributes the same),
    /// emit just the color codes — no reset + re-set of every attribute.
    fn update_rendition(&mut self, fg: Color, bg: Color, flags: u16) {
        match self.current {
            Some((cf, cb, cflags)) if (cf, cb, cflags) == (fg, bg, flags) => return,
            Some((cf, cb, cflags)) if cflags == flags => {
                // Only colors changed: emit the minimal color delta.
                let mut codes: Vec<String> = Vec::new();
                if cf != fg {
                    color_code_explicit(&mut codes, fg, true);
                }
                if cb != bg {
                    color_code_explicit(&mut codes, bg, false);
                }
                self.push(&format!("\x1b[{}m", codes.join(";")));
            }
            _ => self.push(&sgr(fg, bg, flags)),
        }
        self.current = Some((fg, bg, flags));
    }

    fn append_cell(&mut self, cell: &Cell) {
        let mut buf = [0u8; 4];
        self.out
            .extend_from_slice(cell.c.encode_utf8(&mut buf).as_bytes());
        // Re-emit any combining marks so the receiver's emulator reattaches them.
        for &cm in &cell.combining {
            self.out
                .extend_from_slice(cm.encode_utf8(&mut buf).as_bytes());
        }
    }
}

/// Build the full SGR sequence for a rendition (reset, then attributes/colors).
fn sgr(fg: Color, bg: Color, flags: u16) -> String {
    let mut codes: Vec<String> = vec!["0".into()];
    if flags & F_BOLD != 0 {
        codes.push("1".into());
    }
    if flags & F_DIM != 0 {
        codes.push("2".into());
    }
    if flags & F_ITALIC != 0 {
        codes.push("3".into());
    }
    if flags & F_UNDERLINE != 0 {
        codes.push("4".into());
    }
    if flags & F_INVERSE != 0 {
        codes.push("7".into());
    }
    if flags & F_HIDDEN != 0 {
        codes.push("8".into());
    }
    if flags & F_STRIKEOUT != 0 {
        codes.push("9".into());
    }
    push_color(&mut codes, fg, true);
    push_color(&mut codes, bg, false);
    format!("\x1b[{}m", codes.join(";"))
}

/// Like `push_color` but emits the explicit default code (39/49) instead of
/// relying on a preceding reset — for minimal color-only SGR deltas.
fn color_code_explicit(codes: &mut Vec<String>, color: Color, fg: bool) {
    match color {
        Color::Named(NAMED_FOREGROUND) | Color::Named(NAMED_BACKGROUND) => {
            codes.push(if fg { "39".into() } else { "49".into() });
        }
        other => push_color(codes, other, fg),
    }
}

fn push_color(codes: &mut Vec<String>, color: Color, fg: bool) {
    match color {
        // Defaults are implied by the leading reset.
        Color::Named(NAMED_FOREGROUND) | Color::Named(NAMED_BACKGROUND) => {}
        Color::Named(n) if n < 8 => codes.push(((if fg { 30 } else { 40 }) + n).to_string()),
        Color::Named(n) if n < 16 => {
            codes.push(((if fg { 90 } else { 100 }) + (n - 8)).to_string())
        }
        Color::Named(_) => {} // other named slots → terminal default
        Color::Indexed(i) => {
            codes.push(if fg { "38".into() } else { "48".into() });
            codes.push("5".into());
            codes.push(i.to_string());
        }
        Color::Rgb(r, g, b) => {
            codes.push(if fg { "38".into() } else { "48".into() });
            codes.push("2".into());
            codes.push(r.to_string());
            codes.push(g.to_string());
            codes.push(b.to_string());
        }
    }
}

/// Produce the escape sequence transforming `old` into `new`. With
/// `initialized == false`, the screen is fully repainted (clear + redraw),
/// matching mosh's first frame.
pub fn new_frame(old: &Screen, new: &Screen, initialized: bool) -> Vec<u8> {
    let mut frame = FrameState::new(old);

    // A dimensions mismatch forces a full repaint (the receiver starts blank).
    let resized = old.cols != new.cols || old.rows != new.rows;
    let initialized = initialized && !resized;

    // Title (OSC 0): always on a full repaint, otherwise only when it changed.
    if !initialized || old.title != new.title {
        frame.push("\x1b]0;");
        frame.push(&new.title);
        frame.out.push(0x07);
    }

    if !initialized {
        frame.push("\x1b[0m\x1b[H\x1b[2J");
        frame.cursor_x = 0;
        frame.cursor_y = 0;
        // The leading reset establishes a known default pen.
        frame.current = Some((
            Color::Named(NAMED_FOREGROUND),
            Color::Named(NAMED_BACKGROUND),
            0,
        ));
        frame.current_link = Some(None);
    }

    // On a full repaint, hide the cursor up front (mosh does this). On an
    // incremental frame, append_silent_move hides it lazily only when needed.
    if !initialized {
        frame.cursor_visible = false;
        frame.push("\x1b[?25l");
    }

    // Single O(N) pass over the grid: record which rows changed (old vs new) and
    // the changed band `[band_top, band_bottom]`. The cell array is large, so this
    // one scan — shared by scroll detection *and* put_row's redraw decision —
    // replaces the two full-screen scans the old code did (one in scroll
    // detection, one per-row in put_row), which dominated the cost of a typical
    // small diff. (`initialized` already implies matching dimensions.)
    let mut row_changed = vec![false; new.rows as usize];
    let (mut band_top, mut band_bottom): (Option<u16>, u16) = (None, 0);
    if initialized {
        let w = new.cols as usize;
        for y in 0..new.rows {
            let yi = y as usize * w;
            if old.cells[yi..yi + w] != new.cells[yi..yi + w] {
                row_changed[y as usize] = true;
                band_top.get_or_insert(y);
                band_bottom = y;
            }
        }
    }

    // Vertical-scroll detection: if `new` is `old` with a (sub-)region scrolled
    // up or down, emit a cheap scroll (a few line feeds / reverse-indexes, with a
    // scroll region for sub-regions) and redraw only the exposed rows. Only worth
    // attempting when ≥2 rows changed (a scroll shifts a band); the k-search runs
    // over the already-found band, not the whole screen. The synthesized
    // `baseline` models exactly what the emitted escapes do, so the put_row pass
    // redraws only the genuine remainder — and the round-trip stays exact.
    let mut baseline_owned: Option<Screen> = None;
    let mut scrolled = false;
    if let Some(top) = band_top {
        if band_bottom > top && new.rows >= 2 {
            if let Some(op) = scroll_in_band(old, new, top, band_bottom) {
                // Scrolls fill newly-exposed lines with the *current* pen's
                // background (BCE). Reset to the default pen first so exposed rows
                // match the default-blank scrolled baseline.
                frame.update_rendition(
                    Color::Named(NAMED_FOREGROUND),
                    Color::Named(NAMED_BACKGROUND),
                    0,
                );
                emit_scroll(&mut frame, new.rows, op);
                baseline_owned = Some(apply_scroll(old, op));
                scrolled = true;
            }
        }
    }
    let baseline = baseline_owned.as_ref().unwrap_or(old);

    for y in 0..new.rows {
        // After a scroll the baseline differs from `old`, so the old-vs-new change
        // bitmap no longer applies — have put_row re-diff against the baseline.
        // Otherwise we already know which rows changed, so put_row skips its scan.
        let known = if initialized && !scrolled {
            Some(row_changed[y as usize])
        } else {
            None
        };
        put_row(&mut frame, baseline, new, y, initialized, known);
    }

    // Final cursor position.
    if !initialized
        || new.cursor_row as i32 != frame.cursor_y
        || new.cursor_col as i32 != frame.cursor_x
    {
        frame.append_move(new.cursor_row as i32, new.cursor_col as i32);
    }

    // Cursor visibility.
    if !initialized || new.cursor_visible != frame.cursor_visible {
        frame.push(if new.cursor_visible {
            "\x1b[?25h"
        } else {
            "\x1b[?25l"
        });
        frame.cursor_visible = new.cursor_visible;
    }

    // Terminal modes: bracketed paste, mouse reporting, cursor style.
    emit_modes(&mut frame, old, new, initialized);

    frame.out
}

/// Emit DECSET/DECRST + DECSCUSR for the modes that changed (or all, on a full
/// repaint), so the client's real terminal matches the server's.
fn emit_modes(frame: &mut FrameState, old: &Screen, new: &Screen, initialized: bool) {
    use crate::screen::{MOUSE_CLICK, MOUSE_DRAG, MOUSE_MOTION, MOUSE_SGR};

    let set = |frame: &mut FrameState, code: u32, on: bool| {
        frame.push(&format!("\x1b[?{code}{}", if on { 'h' } else { 'l' }));
    };

    if !initialized || old.bracketed_paste != new.bracketed_paste {
        set(frame, 2004, new.bracketed_paste);
    }
    if !initialized || old.app_cursor_keys != new.app_cursor_keys {
        set(frame, 1, new.app_cursor_keys); // DECCKM (application cursor keys)
    }
    if !initialized || old.focus_event != new.focus_event {
        set(frame, 1004, new.focus_event);
    }
    if !initialized || old.alternate_scroll != new.alternate_scroll {
        set(frame, 1007, new.alternate_scroll);
    }
    for (bit, code) in [
        (MOUSE_CLICK, 1000),
        (MOUSE_DRAG, 1002),
        (MOUSE_MOTION, 1003),
        (MOUSE_SGR, 1006),
    ] {
        if !initialized || (old.mouse_mode & bit) != (new.mouse_mode & bit) {
            set(frame, code, new.mouse_mode & bit != 0);
        }
    }

    // OSC 52 clipboard (server→client). Latest-wins: re-emit only when it
    // changed (or on a full repaint, so a reconnecting client re-syncs). We only
    // ever set it, never clear it — the emulator's listener doesn't revert to
    // `None`, so an unset→set transition is the only case.
    if new.clipboard.is_some() && (!initialized || old.clipboard != new.clipboard) {
        if let Some(text) = &new.clipboard {
            use base64::Engine;
            let b64 = base64::engine::general_purpose::STANDARD.encode(text);
            frame.push(&format!("\x1b]52;c;{b64}\x1b\\"));
        }
    }

    if !initialized || old.cursor_shape != new.cursor_shape || old.cursor_blink != new.cursor_blink
    {
        // DECSCUSR: 1/2 block, 3/4 underline, 5/6 beam (odd = blink).
        let base = match new.cursor_shape {
            crate::screen::CURSOR_UNDERLINE => 3,
            crate::screen::CURSOR_BEAM => 5,
            _ => 1,
        };
        let n = base + if new.cursor_blink { 0 } else { 1 };
        frame.push(&format!("\x1b[{n} q"));
    }

    // Terminal bell: emit one BEL (^G) per beep that happened since `old`. The
    // count is monotonic and the receiver's emulator re-counts these, so the diff
    // round-trips exactly. (A full repaint re-rings any accumulated bells, which
    // is bounded and rare.) BEL doesn't move the cursor, so emitting it here is safe.
    let beeps = new.bell_count.saturating_sub(old.bell_count);
    for _ in 0..beeps {
        frame.out.push(0x07);
    }
}

#[allow(clippy::too_many_arguments)]
fn put_row(
    frame: &mut FrameState,
    old: &Screen,
    new: &Screen,
    y: u16,
    initialized: bool,
    known_changed: Option<bool>,
) {
    let width = new.cols;
    let same_dims = old.cols == new.cols && old.rows == new.rows;

    // Identical row (when comparable) needs nothing. `known_changed` lets the
    // caller skip this per-row scan when it already computed the change set in a
    // single shared pass; `None` falls back to scanning the row here.
    if initialized && same_dims && y < old.rows {
        match known_changed {
            Some(false) => return,
            Some(true) => {}
            None => {
                if row_eq(old, new, y) {
                    return;
                }
            }
        }
    }

    let mut x: u16 = 0;
    let mut clear_count: u16 = 0;
    let mut blank_bg = Color::Named(NAMED_BACKGROUND);

    while x < width {
        let cell = new.cell(y, x).unwrap();

        // Skip cells unchanged from old (only when not mid-blank-run).
        if initialized
            && same_dims
            && clear_count == 0
            && y < old.rows
            && cells_eq(cell, old.cell(y, x).unwrap())
        {
            x += cell_width(cell) as u16;
            continue;
        }

        // Accumulate runs of erasable blank cells sharing a background.
        if is_blank(cell) {
            if clear_count == 0 {
                blank_bg = cell.bg;
            }
            if cell.bg == blank_bg {
                clear_count += 1;
                x += 1;
                continue;
            }
        }

        // Flush a pending blank run before drawing a non-blank cell.
        if clear_count > 0 {
            flush_blanks(frame, y, x, clear_count, blank_bg, false);
            clear_count = 0;
            if is_blank(cell) {
                blank_bg = cell.bg;
                clear_count = 1;
                x += 1;
                continue;
            }
        }

        // Draw a visible cell.
        frame.append_silent_move(y as i32, x as i32);
        frame.update_rendition(cell.fg, cell.bg, cell.flags);
        frame.update_hyperlink(&cell.hyperlink);
        frame.append_cell(cell);
        frame.cursor_x += cell_width(cell);
        x += cell_width(cell) as u16;
        // Trash our tracked cursor (forcing the next move to be explicit) when
        // the real cursor position becomes ambiguous: at the final column
        // (pending-wrap), or after emitting a control-character cell (e.g. a
        // stored TAB, which the receiver re-interprets and advances differently).
        if x >= width || (cell.c as u32) < 0x20 || cell.c == '\u{7f}' {
            frame.cursor_x = -1;
            frame.cursor_y = -1;
        }
    }

    // Trailing blank run → erase to end of line (or spaces).
    if clear_count > 0 {
        flush_blanks(frame, y, width, clear_count, blank_bg, true);
    }
}

fn flush_blanks(frame: &mut FrameState, y: u16, x_end: u16, count: u16, bg: Color, at_eol: bool) {
    let start = x_end - count;
    frame.append_silent_move(y as i32, start as i32);
    // Erasable blanks have default fg, no flags, and no hyperlink.
    frame.update_rendition(Color::Named(NAMED_FOREGROUND), bg, 0);
    frame.update_hyperlink(&None);
    if at_eol {
        // Erase to end of line (BCE fills with current bg).
        frame.push("\x1b[K");
    } else if count > 4 {
        // Erase n characters.
        frame.push(&format!("\x1b[{count}X"));
    } else {
        frame.push_n(count as usize, b' ');
        frame.cursor_x = x_end as i32;
    }
}

fn cells_eq(a: &Cell, b: &Cell) -> bool {
    a == b
}

fn row_eq(old: &Screen, new: &Screen, y: u16) -> bool {
    (0..new.cols).all(|x| match (old.cell(y, x), new.cell(y, x)) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    })
}

/// A detected vertical scroll: a row range `[top, bottom]` (inclusive) shifted by
/// `k` rows, up or down. A whole-screen scroll is `top == 0 && bottom == rows-1`
/// and is emitted without a scroll region (plain LF/RI); a sub-region uses
/// DECSTBM. The exposed `k` rows become blank in the baseline and are redrawn.
#[derive(Clone, Copy, Debug)]
struct Scroll {
    top: u16,
    bottom: u16,
    k: u16,
    down: bool,
}

/// Detect whether the already-found changed band `[top, bottom]` (with
/// `bottom > top`) is explained by a single vertical scroll within it. The caller
/// finds the band in its own single grid pass; this does only the k-search, so
/// the expensive full-screen scan isn't repeated. Returns the smallest-`k` scroll,
/// preferring up over down. `None` if no single scroll explains the band.
fn scroll_in_band(old: &Screen, new: &Screen, top: u16, bottom: u16) -> Option<Scroll> {
    let w = new.cols as usize;
    let row_eq = |a: u16, b: u16| {
        let ai = a as usize * w;
        let bi = b as usize * w;
        old.cells[ai..ai + w] == new.cells[bi..bi + w]
    };
    let region_h = bottom - top + 1;

    // Scroll up by k within [top, bottom]: new[top+i] == old[top+i+k].
    for k in 1..region_h {
        if (0..region_h - k).all(|i| row_eq(top + i + k, top + i)) {
            return Some(Scroll {
                top,
                bottom,
                k,
                down: false,
            });
        }
    }
    // Scroll down by k within [top, bottom]: new[top+k+i] == old[top+i].
    for k in 1..region_h {
        if (0..region_h - k).all(|i| row_eq(top + i, top + k + i)) {
            return Some(Scroll {
                top,
                bottom,
                k,
                down: true,
            });
        }
    }
    None
}

/// Emit the escape sequence that performs `op`, leaving `frame`'s tracked cursor
/// consistent with where the real cursor ends up.
fn emit_scroll(frame: &mut FrameState, rows: u16, op: Scroll) {
    let whole = op.top == 0 && op.bottom == rows - 1;
    if whole && !op.down {
        // Whole screen up: LFs at the bottom row scroll the screen up.
        frame.append_move(rows as i32 - 1, 0);
        frame.push_n(op.k as usize, b'\n');
        frame.cursor_x = 0;
        frame.cursor_y = rows as i32 - 1;
        return;
    }
    if whole && op.down {
        // Whole screen down: reverse-indexes at the top row scroll the screen down.
        frame.append_move(0, 0);
        for _ in 0..op.k {
            frame.push("\x1bM"); // RI
        }
        frame.cursor_x = 0;
        frame.cursor_y = 0;
        return;
    }
    // Sub-region: set the scroll region (DECSTBM), scroll at the appropriate
    // margin, then reset the region. DECSTBM and its reset both home the cursor,
    // so mark our tracked position unknown to force an explicit move next.
    frame.push(&format!("\x1b[{};{}r", op.top + 1, op.bottom + 1));
    if op.down {
        frame.push(&format!("\x1b[{};1H", op.top + 1));
        for _ in 0..op.k {
            frame.push("\x1bM"); // RI at the top margin scrolls the region down
        }
    } else {
        frame.push(&format!("\x1b[{};1H", op.bottom + 1));
        frame.push_n(op.k as usize, b'\n'); // LF at the bottom margin scrolls up
    }
    frame.push("\x1b[r"); // reset scroll region to the full screen
    frame.cursor_x = -1;
    frame.cursor_y = -1;
}

/// `old` with `op` applied: rows in `[top, bottom]` shifted by `k`, the exposed
/// `k` rows blanked. Rows outside the region are untouched. Models exactly what
/// [`emit_scroll`]'s escapes do to the screen, so it's the correct put_row baseline.
fn apply_scroll(old: &Screen, op: Scroll) -> Screen {
    let mut s = old.clone();
    let w = old.cols as usize;
    let blank_row = |s: &mut Screen, row: u16| {
        let di = row as usize * w;
        for c in &mut s.cells[di..di + w] {
            *c = Cell::default();
        }
    };
    let copy_row = |s: &mut Screen, dst: u16, src: u16| {
        let di = dst as usize * w;
        let si = src as usize * w;
        s.cells[di..di + w].clone_from_slice(&old.cells[si..si + w]);
    };
    for i in op.top..=op.bottom {
        if op.down {
            // Row i takes old row i-k (within the region); top k rows exposed.
            if i >= op.top + op.k {
                copy_row(&mut s, i, i - op.k);
            } else {
                blank_row(&mut s, i);
            }
        } else {
            // Row i takes old row i+k (within the region); bottom k rows exposed.
            if i + op.k <= op.bottom {
                copy_row(&mut s, i, i + op.k);
            } else {
                blank_row(&mut s, i);
            }
        }
    }
    s
}
