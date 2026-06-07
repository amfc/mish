//! [`Emulator`]: an alacritty-terminal-backed VT emulator that consumes PTY
//! output bytes and produces [`Screen`] snapshots for synchronization.
//!
//! This is the only place that touches `alacritty_terminal`; everything the
//! protocol synchronizes is the plain-data [`Screen`] this produces. The server
//! feeds child-process output into [`Emulator::feed`] and calls
//! [`Emulator::snapshot`] to get the state to hand to the SSP layer.

use std::sync::{Arc, Mutex};

use alacritty_terminal::event::{Event, EventListener, WindowSize};
use alacritty_terminal::grid::Dimensions;
use alacritty_terminal::index::{Column, Line};
use alacritty_terminal::term::cell::{Cell as ATermCell, Flags};
use alacritty_terminal::term::{ClipboardType, Config, TermMode};
use alacritty_terminal::vte::ansi::{Color as ATermColor, CursorShape, NamedColor, Processor, Rgb};
use alacritty_terminal::{term::test::TermSize, Term};

use crate::screen::{self, Cell, Color, Screen};

/// Event listener that records out-of-band terminal events we don't carry in the
/// cell grid: window title, OSC 52 clipboard (latest-wins), and — crucially —
/// **host answerbacks**. Terminal query sequences a program sends (Device
/// Attributes, cursor-position report, status report, OSC color queries, text-
/// area size) make alacritty emit a reply the *terminal* must write back to the
/// program's input. We buffer those replies in `answerback`; the server drains
/// them after each feed and writes them to the child PTY (mirroring mosh's
/// `terminal_to_host`). Without this, programs that probe the terminal at startup
/// (vim, tmux, less, `tput`) hang or fall back to wrong defaults.
#[derive(Clone, Default)]
struct TermListener {
    title: Arc<Mutex<String>>,
    clipboard: Arc<Mutex<Option<String>>>,
    answerback: Arc<Mutex<Vec<u8>>>,
    /// Current screen size `(cols, rows)`, for text-area-size replies.
    size: Arc<Mutex<(u16, u16)>>,
    /// Monotonic count of terminal bells (BEL) seen.
    bell_count: Arc<Mutex<u64>>,
}

impl TermListener {
    fn push_answerback(&self, reply: &str) {
        self.answerback
            .lock()
            .unwrap()
            .extend_from_slice(reply.as_bytes());
    }
}

impl EventListener for TermListener {
    fn send_event(&self, event: Event) {
        match event {
            Event::Title(t) => *self.title.lock().unwrap() = t,
            Event::ResetTitle => self.title.lock().unwrap().clear(),
            // OSC 52 copy (the system clipboard, not the X primary selection).
            Event::ClipboardStore(ClipboardType::Clipboard, text) => {
                *self.clipboard.lock().unwrap() = Some(text);
            }
            // Direct answerback (DA1/secondary DA, DSR, CPR, DECRQSS, DECRQM, …).
            Event::PtyWrite(text) => self.push_answerback(&text),
            // OSC 4/10/11 color query: answer with the standard default palette
            // for the index (correct for an unmodified palette — the common case).
            Event::ColorRequest(index, format) => {
                self.push_answerback(&format(default_palette_rgb(index)));
            }
            // Terminal bell (BEL / ^G) — counted; the diff replays the delta.
            Event::Bell => *self.bell_count.lock().unwrap() += 1,
            // CSI 14/18 t text-area size: answer in cells (we have no pixel size).
            Event::TextAreaSizeRequest(format) => {
                let (cols, rows) = *self.size.lock().unwrap();
                self.push_answerback(&format(WindowSize {
                    num_lines: rows,
                    num_cols: cols,
                    cell_width: 0,
                    cell_height: 0,
                }));
            }
            _ => {}
        }
    }
}

/// The standard xterm 256-color palette entry for `index`, used to answer OSC
/// color queries when the palette hasn't been customized. Indices ≥ 256 are the
/// default foreground/background.
fn default_palette_rgb(index: usize) -> Rgb {
    // The 16 base ANSI colors (xterm values).
    const ANSI16: [(u8, u8, u8); 16] = [
        (0, 0, 0),
        (205, 0, 0),
        (0, 205, 0),
        (205, 205, 0),
        (0, 0, 238),
        (205, 0, 205),
        (0, 205, 205),
        (229, 229, 229),
        (127, 127, 127),
        (255, 0, 0),
        (0, 255, 0),
        (255, 255, 0),
        (92, 92, 255),
        (255, 0, 255),
        (0, 255, 255),
        (255, 255, 255),
    ];
    let (r, g, b) = match index {
        0..=15 => ANSI16[index],
        16..=231 => {
            const LEVELS: [u8; 6] = [0, 95, 135, 175, 215, 255];
            let i = index - 16;
            (LEVELS[(i / 36) % 6], LEVELS[(i / 6) % 6], LEVELS[i % 6])
        }
        232..=255 => {
            let v = 8 + 10 * (index - 232) as u8;
            (v, v, v)
        }
        // Default foreground (256) and anything else; background (257) is black.
        257 => (0, 0, 0),
        _ => (229, 229, 229),
    };
    Rgb { r, g, b }
}

/// A VT emulator producing [`Screen`] snapshots.
pub struct Emulator {
    term: Term<TermListener>,
    parser: Processor,
    listener: TermListener,
}

/// Clamp a reported terminal size to at least 1×1. The grid backing the emulator
/// computes row/column deltas with unsigned subtraction, which underflows (panic
/// in debug, garbage in release) for a zero dimension — so a client that hasn't
/// learned its window size yet, or a malicious one, can't crash the session.
fn clamp_size(cols: u16, rows: u16) -> (u16, u16) {
    (cols.max(1), rows.max(1))
}

impl Emulator {
    /// Create an emulator with the given screen size.
    pub fn new(cols: u16, rows: u16) -> Self {
        let (cols, rows) = clamp_size(cols, rows);
        let listener = TermListener::default();
        *listener.size.lock().unwrap() = (cols, rows);
        let size = TermSize::new(cols as usize, rows as usize);
        let term = Term::new(Config::default(), &size, listener.clone());
        Self {
            term,
            parser: Processor::new(),
            listener,
        }
    }

    /// Feed a chunk of PTY output (child → terminal).
    pub fn feed(&mut self, bytes: &[u8]) {
        self.parser.advance(&mut self.term, bytes);
    }

    /// Take any pending host answerback the last [`feed`](Self::feed) produced
    /// (terminal query replies the server must write back to the child PTY).
    /// Empties the buffer.
    pub fn take_answerback(&self) -> Vec<u8> {
        let mut buf = self.listener.answerback.lock().unwrap();
        std::mem::take(&mut *buf)
    }

    /// Resize the emulated screen. A zero dimension (an unconfigured or hostile
    /// client reporting a 0×0 window) is clamped to 1: the backing grid's resize
    /// math underflows on a zero size and would otherwise panic the session.
    pub fn resize(&mut self, cols: u16, rows: u16) {
        let (cols, rows) = clamp_size(cols, rows);
        *self.listener.size.lock().unwrap() = (cols, rows);
        self.term
            .resize(TermSize::new(cols as usize, rows as usize));
    }

    pub fn cols(&self) -> u16 {
        self.term.columns() as u16
    }

    pub fn rows(&self) -> u16 {
        self.term.screen_lines() as u16
    }

    /// Wrap a fresh emulator in a shareable `Arc<Mutex<…>>` — the form the server
    /// session and the scrollback side-channel both hold (the server feeds it;
    /// the history server reads its scrollback). Locks are always brief.
    pub fn shared(cols: u16, rows: u16) -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self::new(cols, rows)))
    }

    /// Number of scrollback (history) lines currently retained *above* the
    /// visible screen — how far back a client can scroll.
    pub fn history_size(&self) -> u32 {
        self.term.grid().history_size() as u32
    }

    /// Read a window of `count` rows for scrollback display, starting
    /// `top_above` lines above the top visible row (`top_above == 0` starts at
    /// the live top row; larger values reach further into history). The window
    /// may straddle history and the visible screen; rows outside the available
    /// range (older than the oldest history line, or below the screen) are
    /// omitted. Each row is the same `Cell` vector as a [`Screen`] row.
    pub fn history_lines(&self, top_above: u32, count: u16) -> Vec<Vec<Cell>> {
        let grid = self.term.grid();
        let cols = self.term.columns();
        let screen_rows = self.term.screen_lines() as i64;
        let history = grid.history_size() as i64;

        // First requested grid line: negative = history, >= 0 = visible screen.
        let start = -(top_above as i64);
        let mut out = Vec::with_capacity(count as usize);
        for i in 0..count as i64 {
            let line = start + i;
            if line < -history || line >= screen_rows {
                continue; // outside the retained range
            }
            let row = &grid[Line(line as i32)];
            out.push((0..cols).map(|c| convert_cell(&row[Column(c)])).collect());
        }
        out
    }

    /// Capture the current visible screen as a synchronizable [`Screen`].
    pub fn snapshot(&self) -> Screen {
        let cols = self.term.columns();
        let rows = self.term.screen_lines();
        let grid = self.term.grid();

        let mut cells = Vec::with_capacity(cols * rows);
        for r in 0..rows {
            let row = &grid[Line(r as i32)];
            for c in 0..cols {
                let aterm_cell = &row[Column(c)];
                let mut cell = convert_cell(aterm_cell);
                // Normalize a "broken" wide char: a WIDE_CHAR whose following
                // column is not its spacer (the spacer was overwritten by a real
                // glyph after an insert/delete — ICH/DCH — shifted into it). The
                // glyph stream can't reproduce that state: re-emitting the wide
                // glyph re-claims the spacer, and writing the partner glyph onto a
                // spacer makes the terminal clear the wide char — so the receiver
                // renders blank there. Store blank to match, keeping every snapshot
                // reconstructible (same spirit as the control-char normalization in
                // `convert_cell`). Found by the `diff_roundtrip` fuzzer.
                if aterm_cell.flags.contains(Flags::WIDE_CHAR)
                    && !(c + 1 < cols
                        && row[Column(c + 1)].flags.contains(Flags::WIDE_CHAR_SPACER))
                {
                    cell.c = ' ';
                    cell.combining.clear();
                }
                cells.push(cell);
            }
        }

        let cursor = grid.cursor.point;
        let mode = *self.term.mode();
        let mut mouse_mode = 0u8;
        if mode.contains(TermMode::MOUSE_REPORT_CLICK) {
            mouse_mode |= screen::MOUSE_CLICK;
        }
        if mode.contains(TermMode::MOUSE_DRAG) {
            mouse_mode |= screen::MOUSE_DRAG;
        }
        if mode.contains(TermMode::MOUSE_MOTION) {
            mouse_mode |= screen::MOUSE_MOTION;
        }
        if mode.contains(TermMode::SGR_MOUSE) {
            mouse_mode |= screen::MOUSE_SGR;
        }
        let style = self.term.cursor_style();
        let cursor_shape = match style.shape {
            CursorShape::Underline => screen::CURSOR_UNDERLINE,
            CursorShape::Beam => screen::CURSOR_BEAM,
            _ => screen::CURSOR_BLOCK, // Block / HollowBlock / Hidden
        };

        Screen {
            cols: cols as u16,
            rows: rows as u16,
            cells,
            cursor_row: cursor.line.0.max(0) as u16,
            cursor_col: cursor.column.0 as u16,
            cursor_visible: mode.contains(TermMode::SHOW_CURSOR),
            // Normalize the title to exactly what survives a clean OSC round-trip:
            // strip control chars (new_frame strips them on emit) and leading +
            // trailing whitespace (alacritty drops both when re-parsing the emitted
            // title). Trimming *both* ends matters because osc_sanitize removes a
            // control char that was sitting at an edge — which alacritty had let
            // protect an adjacent space — exposing whitespace the wire diff can't
            // reproduce (alacritty re-strips it), breaking round-trip identity.
            // Found by the diff_roundtrip fuzzer (leading-space case: "\x8f &").
            // trim() never drops a *legitimate* edge space: alacritty already
            // stripped those at the original parse, before snapshot ran.
            title: crate::display::osc_sanitize(&self.listener.title.lock().unwrap())
                .trim()
                .to_string(),
            echo_ack: 0, // set by the server session, not the emulator
            bracketed_paste: mode.contains(TermMode::BRACKETED_PASTE),
            mouse_mode,
            cursor_shape,
            cursor_blink: style.blinking,
            focus_event: mode.contains(TermMode::FOCUS_IN_OUT),
            alternate_scroll: mode.contains(TermMode::ALTERNATE_SCROLL),
            alt_screen: mode.contains(TermMode::ALT_SCREEN),
            clipboard: self.listener.clipboard.lock().unwrap().clone(),
            app_cursor_keys: mode.contains(TermMode::APP_CURSOR),
            bell_count: *self.listener.bell_count.lock().unwrap(),
        }
    }
}

fn convert_cell(cell: &ATermCell) -> Cell {
    // The emulator may store a control character as a cell glyph (e.g. a TAB,
    // kept for reflow). Such a cell renders as blank and can't be reproduced by
    // re-emitting the control byte (the receiver re-interprets it), so we
    // normalize it to a space — visually identical, and it round-trips.
    let c = if (cell.c as u32) < 0x20 || cell.c == '\u{7f}' {
        ' '
    } else {
        cell.c
    };
    Cell {
        c,
        fg: convert_color(cell.fg),
        bg: convert_color(cell.bg),
        flags: convert_flags(cell.flags),
        combining: cell.zerowidth().map(|z| z.to_vec()).unwrap_or_default(),
        // Sanitize id/URI the same way new_frame does on emit, so the OSC 8
        // hyperlink round-trips (control bytes here would be stripped on render).
        // A hyperlink whose URI is empty (or sanitizes to empty) is an OSC 8
        // *close*, not a link: re-emitting it produces no hyperlink, so store None
        // to match (alacritty can leave a degenerate empty-URI link with an
        // auto-generated id — found by the diff_roundtrip fuzzer).
        hyperlink: cell.hyperlink().and_then(|h| {
            let uri = crate::display::osc_sanitize(h.uri()).into_owned();
            (!uri.is_empty()).then(|| screen::Hyperlink {
                id: Some(crate::display::osc_sanitize(h.id()).into_owned()),
                uri,
            })
        }),
    }
}

fn convert_color(color: ATermColor) -> Color {
    match color {
        ATermColor::Named(named) => Color::Named(named as u16),
        ATermColor::Indexed(i) => Color::Indexed(i),
        ATermColor::Spec(rgb) => Color::Rgb(rgb.r, rgb.g, rgb.b),
    }
}

fn convert_flags(flags: Flags) -> u16 {
    // Only display attributes are stored. WIDE_CHAR / WIDE_CHAR_SPACER are
    // deliberately omitted: cell geometry is derived from the character's own
    // display width (the receiver re-derives it when it replays the glyph), so
    // storing the flags would be redundant state that diverges on erase.
    let mut out = 0u16;
    let map = [
        (Flags::INVERSE, screen::F_INVERSE),
        (Flags::BOLD, screen::F_BOLD),
        (Flags::ITALIC, screen::F_ITALIC),
        (Flags::UNDERLINE, screen::F_UNDERLINE),
        (Flags::DIM, screen::F_DIM),
        (Flags::HIDDEN, screen::F_HIDDEN),
        (Flags::STRIKEOUT, screen::F_STRIKEOUT),
    ];
    for (af, mf) in map {
        if flags.contains(af) {
            out |= mf;
        }
    }
    out
}

/// Expose the default named-color discriminants so [`crate::screen`] sentinels
/// and emulator output agree (compile-time check).
#[allow(dead_code)]
const _: () = {
    // Foreground/Background are stable NamedColor variants; this just documents
    // the dependency. Real cells are always overwritten on resize, so sentinel
    // mismatch can never survive into a compared state.
    let _ = NamedColor::Foreground;
    let _ = NamedColor::Background;
};

#[cfg(test)]
mod tests {
    use super::*;

    /// A Device Status Report (cursor position) query must produce a CPR reply
    /// the server can write back to the child. Without it, programs that measure
    /// the cursor (prompt width detection, vim, …) hang.
    #[test]
    fn dsr_cursor_position_reply() {
        let mut emu = Emulator::new(80, 24);
        emu.feed(b"abc"); // cursor now at row 1, col 4 (1-based)
        emu.feed(b"\x1b[6n"); // DSR: report cursor position
        assert_eq!(emu.take_answerback(), b"\x1b[1;4R");
        // Draining empties the buffer.
        assert!(emu.take_answerback().is_empty());
    }

    /// Primary Device Attributes (`ESC[c`) must be answered (programs use it to
    /// detect terminal capabilities at startup).
    #[test]
    fn device_attributes_reply() {
        let mut emu = Emulator::new(80, 24);
        emu.feed(b"\x1b[c");
        let reply = emu.take_answerback();
        assert!(
            reply.starts_with(b"\x1b[?") && reply.ends_with(b"c"),
            "DA1 reply should be a CSI ? … c sequence, got {:?}",
            String::from_utf8_lossy(&reply)
        );
    }

    /// A 0-dimension size (a client that hasn't learned its window size, or a
    /// hostile one) must not panic: the backing grid's resize underflows on a
    /// zero size. Regression for a server crash when the client reported 0×0.
    #[test]
    fn zero_size_does_not_panic() {
        // Construction with a zero dimension is clamped, not panicked.
        let mut emu = Emulator::new(0, 0);
        assert_eq!((emu.cols(), emu.rows()), (1, 1));
        // …and a resize to a zero dimension is likewise survivable.
        emu.resize(80, 0);
        emu.resize(0, 24);
        emu.resize(0, 0);
        emu.feed(b"x"); // still usable afterward
        emu.resize(80, 24);
        assert_eq!((emu.cols(), emu.rows()), (80, 24));
    }

    /// CSI 18 t (text-area size in cells) is answered from the current size.
    #[test]
    fn text_area_size_reply() {
        let mut emu = Emulator::new(80, 24);
        emu.feed(b"\x1b[18t");
        let reply = emu.take_answerback();
        // xterm form: CSI 8 ; rows ; cols t
        assert_eq!(reply, b"\x1b[8;24;80t");
    }

    #[test]
    fn no_query_no_answerback() {
        let mut emu = Emulator::new(80, 24);
        emu.feed(b"just some text\r\nand more");
        assert!(emu.take_answerback().is_empty());
    }
}
