//! [`Emulator`]: an alacritty-terminal-backed VT emulator that consumes PTY
//! output bytes and produces [`Screen`] snapshots for synchronization.
//!
//! This is the only place that touches `alacritty_terminal`; everything the
//! protocol synchronizes is the plain-data [`Screen`] this produces. The server
//! feeds child-process output into [`Emulator::feed`] and calls
//! [`Emulator::snapshot`] to get the state to hand to the SSP layer.

use std::sync::{Arc, Mutex};

use alacritty_terminal::event::{Event, EventListener};
use alacritty_terminal::grid::Dimensions;
use alacritty_terminal::index::{Column, Line};
use alacritty_terminal::term::cell::{Cell as ATermCell, Flags};
use alacritty_terminal::term::{ClipboardType, Config, TermMode};
use alacritty_terminal::vte::ansi::{Color as ATermColor, CursorShape, NamedColor, Processor};
use alacritty_terminal::{term::test::TermSize, Term};

use crate::screen::{self, Cell, Color, Screen};

/// Event listener that records out-of-band terminal events we synchronize but
/// which aren't part of the cell grid: the window title and the OSC 52 clipboard
/// (latest-wins). Everything else is a no-op.
#[derive(Clone, Default)]
struct TermListener {
    title: Arc<Mutex<String>>,
    clipboard: Arc<Mutex<Option<String>>>,
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
            _ => {}
        }
    }
}

/// A VT emulator producing [`Screen`] snapshots.
pub struct Emulator {
    term: Term<TermListener>,
    parser: Processor,
    listener: TermListener,
}

impl Emulator {
    /// Create an emulator with the given screen size.
    pub fn new(cols: u16, rows: u16) -> Self {
        let listener = TermListener::default();
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

    /// Resize the emulated screen.
    pub fn resize(&mut self, cols: u16, rows: u16) {
        self.term
            .resize(TermSize::new(cols as usize, rows as usize));
    }

    pub fn cols(&self) -> u16 {
        self.term.columns() as u16
    }

    pub fn rows(&self) -> u16 {
        self.term.screen_lines() as u16
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
                cells.push(convert_cell(&row[Column(c)]));
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
            title: self.listener.title.lock().unwrap().clone(),
            echo_ack: 0, // set by the server session, not the emulator
            bracketed_paste: mode.contains(TermMode::BRACKETED_PASTE),
            mouse_mode,
            cursor_shape,
            cursor_blink: style.blinking,
            focus_event: mode.contains(TermMode::FOCUS_IN_OUT),
            alternate_scroll: mode.contains(TermMode::ALTERNATE_SCROLL),
            clipboard: self.listener.clipboard.lock().unwrap().clone(),
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
        hyperlink: cell.hyperlink().map(|h| screen::Hyperlink {
            id: Some(h.id().to_string()),
            uri: h.uri().to_string(),
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
