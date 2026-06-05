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
//! [`crate::screen`]'s `apply_diff`). We deliberately omit a few mosh
//! micro-optimizations (vertical-scroll detection, hyperlinks, mouse/paste
//! modes) — they affect byte count, not correctness.

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

    // Vertical-scroll detection: if `new` is `old` shifted up by k rows, emit a
    // scroll (cheap: a few line feeds at the bottom) and redraw only the exposed
    // rows, instead of repainting every shifted row.
    let mut baseline_owned: Option<Screen> = None;
    if initialized {
        if let Some(k) = detect_scroll_up(old, new) {
            // A line feed fills the newly-exposed line with the *current* pen's
            // background (BCE). Reset to the default pen first so exposed rows
            // match the default-blank `scroll_up` baseline (put_row then redraws
            // any genuinely non-default exposed content).
            frame.update_rendition(
                Color::Named(NAMED_FOREGROUND),
                Color::Named(NAMED_BACKGROUND),
                0,
            );
            frame.append_move(new.rows as i32 - 1, 0);
            frame.push_n(k as usize, b'\n'); // LF at the bottom scrolls up
            frame.cursor_x = 0;
            frame.cursor_y = new.rows as i32 - 1;
            baseline_owned = Some(scroll_up(old, k));
        }
    }
    let baseline = baseline_owned.as_ref().unwrap_or(old);

    for y in 0..new.rows {
        put_row(&mut frame, baseline, new, y, initialized);
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
}

#[allow(clippy::too_many_arguments)]
fn put_row(frame: &mut FrameState, old: &Screen, new: &Screen, y: u16, initialized: bool) {
    let width = new.cols;
    let same_dims = old.cols == new.cols && old.rows == new.rows;

    // Identical row (when comparable) needs nothing.
    if initialized && same_dims && y < old.rows && row_eq(old, new, y) {
        return;
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

/// If `new` equals `old` scrolled up by `k` rows (1..rows) — i.e. the top
/// `rows-k` rows of `new` match the bottom `rows-k` rows of `old` — return the
/// smallest such `k`. Returns `None` if the cells are identical or no scroll
/// relationship holds.
fn detect_scroll_up(old: &Screen, new: &Screen) -> Option<u16> {
    if old.cols != new.cols || old.rows != new.rows || old.rows < 2 {
        return None;
    }
    if old.cells == new.cells {
        return None; // identical — nothing to scroll
    }
    let rows = new.rows;
    let w = new.cols as usize;
    for k in 1..rows {
        let shifted_matches = (0..rows - k).all(|i| {
            let oi = (i + k) as usize * w;
            let ni = i as usize * w;
            old.cells[oi..oi + w] == new.cells[ni..ni + w]
        });
        if shifted_matches {
            return Some(k);
        }
    }
    None
}

/// `old` with its rows shifted up by `k`; the bottom `k` rows become blank.
/// Only the cells matter (used as the put_row baseline after a scroll).
fn scroll_up(old: &Screen, k: u16) -> Screen {
    let mut s = old.clone();
    let rows = old.rows;
    let w = old.cols as usize;
    for i in 0..rows {
        let di = i as usize * w;
        let src = i + k;
        if src < rows {
            let si = src as usize * w;
            s.cells[di..di + w].clone_from_slice(&old.cells[si..si + w]);
        } else {
            for c in &mut s.cells[di..di + w] {
                *c = Cell::default();
            }
        }
    }
    s
}
