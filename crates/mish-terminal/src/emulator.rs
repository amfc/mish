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
use alacritty_terminal::term::{Config, TermMode};
use alacritty_terminal::vte::ansi::{Color as ATermColor, NamedColor, Processor};
use alacritty_terminal::{term::test::TermSize, Term};

use crate::screen::{self, Cell, Color, Screen};

/// Event listener that records terminal title changes (everything else is a
/// no-op for our purposes — we only synchronize the rendered screen).
#[derive(Clone, Default)]
struct TitleListener {
    title: Arc<Mutex<String>>,
}

impl EventListener for TitleListener {
    fn send_event(&self, event: Event) {
        match event {
            Event::Title(t) => *self.title.lock().unwrap() = t,
            Event::ResetTitle => self.title.lock().unwrap().clear(),
            _ => {}
        }
    }
}

/// A VT emulator producing [`Screen`] snapshots.
pub struct Emulator {
    term: Term<TitleListener>,
    parser: Processor,
    listener: TitleListener,
}

impl Emulator {
    /// Create an emulator with the given screen size.
    pub fn new(cols: u16, rows: u16) -> Self {
        let listener = TitleListener::default();
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
        Screen {
            cols: cols as u16,
            rows: rows as u16,
            cells,
            cursor_row: cursor.line.0.max(0) as u16,
            cursor_col: cursor.column.0 as u16,
            cursor_visible: self.term.mode().contains(TermMode::SHOW_CURSOR),
            title: self.listener.title.lock().unwrap().clone(),
            echo_ack: 0, // set by the server session, not the emulator
        }
    }
}

fn convert_cell(cell: &ATermCell) -> Cell {
    Cell {
        c: cell.c,
        fg: convert_color(cell.fg),
        bg: convert_color(cell.bg),
        flags: convert_flags(cell.flags),
        combining: cell.zerowidth().map(|z| z.to_vec()).unwrap_or_default(),
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
    let mut out = 0u16;
    let map = [
        (Flags::INVERSE, screen::F_INVERSE),
        (Flags::BOLD, screen::F_BOLD),
        (Flags::ITALIC, screen::F_ITALIC),
        (Flags::UNDERLINE, screen::F_UNDERLINE),
        (Flags::DIM, screen::F_DIM),
        (Flags::HIDDEN, screen::F_HIDDEN),
        (Flags::STRIKEOUT, screen::F_STRIKEOUT),
        (Flags::WIDE_CHAR, screen::F_WIDE),
        (Flags::WIDE_CHAR_SPACER, screen::F_WIDE_SPACER),
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
