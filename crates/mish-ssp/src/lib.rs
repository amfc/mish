//! # mish-ssp
//!
//! A Rust reimplementation of mosh's **State Synchronization Protocol (SSP)**.
//!
//! SSP keeps two copies of an application state (one per peer) in sync over an
//! **unreliable datagram** channel, with no retransmission queue: each datagram
//! carries a diff from the state the peer is known/assumed to hold, so loss is
//! self-healing — the next datagram simply diffs from further back.
//!
//! ## Layers
//!
//! * [`state::SyncState`] — the trait an application state implements (diff /
//!   apply / equality). [`states::BytesState`] is a simple test impl.
//! * [`core::SspCore`] — the **sans-IO** protocol state machine. No I/O, no
//!   clock: fully deterministic and simulation-friendly.
//! * [`transport::Transport`] — the unreliable datagram wire abstraction.
//!   [`memory`] provides an in-memory implementation with fault injection.
//! * [`session`] — the async driver that runs an [`core::SspCore`] over a
//!   [`transport::Transport`], plus the [`session::Session`] handle trait.
//! * [`sim`] — a synchronous, virtual-time network simulator for the core.
//!
//! The QUIC datagram transport, terminal states, and client/server binaries are
//! separate crates layered on top (see the workspace roadmap).

pub mod clock;
pub mod core;
pub mod frag;
pub mod framing;
pub mod instruction;
pub mod memory;
pub mod session;
pub mod sim;
pub mod state;
pub mod states;
pub mod transport;

/// Kani bounded-proof harnesses (run with `cargo kani`). Gated out of every
/// normal build/test — see the module docs for what is and isn't provable here.
#[cfg(kani)]
mod kani_proofs;

/// Exhaustive bounded model checking of SSP convergence (run with
/// `cargo test -p mish-ssp`). Drives the real [`core::SspCore`] transition
/// functions through every schedule interleaving up to a bounded scenario length
/// — see the module docs for the safety/liveness properties and the bound.
#[cfg(test)]
mod stateright_model;

pub use clock::{Clock, Millis, SystemClock, TokioClock};
pub use core::{SspConfig, SspCore};
pub use instruction::Instruction;
pub use session::{Driver, Session, SessionError, SessionHandle};
pub use state::SyncState;
pub use transport::{Transport, TransportError};
