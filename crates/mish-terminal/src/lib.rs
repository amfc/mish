//! # mish-terminal
//!
//! The terminal layer for mish: the two application states the
//! [State Synchronization Protocol](mish_ssp) keeps in sync, plus an emulator
//! that produces them.
//!
//! * [`screen::Screen`] — the **`Complete`** state (server → client): a snapshot
//!   of the rendered terminal screen, with a row-granular diff so only changed
//!   rows travel the wire.
//! * [`user::UserStream`] — the **`UserStream`** state (client → server): an
//!   append-only, trimmable log of keystrokes and resizes.
//! * [`emulator::Emulator`] — an `alacritty_terminal`-backed VT emulator that
//!   consumes PTY output and yields [`screen::Screen`] snapshots. This is the
//!   only alacritty-coupled piece; the states above are pure data.
//! * [`render`] — paints a [`screen::Screen`] back onto a real TTY (client side).
//!
//! A mish **client** is an [`mish_ssp::SspCore`]`<UserStream, Screen>`; the
//! **server** is its mirror, `SspCore<Screen, UserStream>`.

pub mod emulator;
pub mod render;
pub mod screen;
pub mod user;

pub use emulator::Emulator;
pub use render::render_full;
pub use screen::{Cell, Color, Screen};
pub use user::{UserEvent, UserStream};
