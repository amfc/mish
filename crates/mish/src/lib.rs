//! # mosh
//!
//! The mish client and server: a roaming, low-latency remote shell built from
//! the layered crates below it.
//!
//! * The **server** ([`server::run_server`]) runs a child shell on a PTY, feeds
//!   its output through the [`mish_terminal::Emulator`] into a synchronized
//!   `Screen`, and applies the client's `UserStream` keystrokes/resizes back to
//!   the PTY.
//! * The **client** ([`client::run_client`]) forwards the user's keystrokes as a
//!   `UserStream` and paints each received `Screen` onto the real terminal.
//!
//! Both session loops are generic over [`mish_ssp::Transport`] and decoupled
//! from real I/O via channels, so they are tested headlessly over the in-memory
//! transport (`tests/loopback.rs`). The binaries (`mish-server`, `mish-client`)
//! wire a real PTY and TTY over the QUIC transport ([`mish_quic`]).

pub mod bootstrap;
pub mod client;
pub mod locale;
pub mod pty;
pub mod server;

pub use bootstrap::Bootstrap;
pub use client::{run_client, ClientInput};
pub use server::{run_server, PtyControl};
