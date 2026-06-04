//! The [`Transport`] trait: an unreliable datagram wire.
//!
//! This is the seam between the protocol and the network. The SSP core produces
//! and consumes opaque datagrams; a `Transport` best-effort delivers them. It is
//! deliberately tiny and matches what QUIC's unreliable-datagram extension
//! offers (and what UDP offers): send may silently drop, recv yields whatever
//! arrives, in whatever order.
//!
//! Methods take `&self` (not `&mut self`) so a transport can be cheaply shared
//! between the send loop and the receive loop. Implementations use interior
//! mutability (channels, `quinn::Connection`, …).

use bytes::Bytes;
use std::fmt::Debug;

/// Errors a transport can surface. The protocol treats most send errors as a
/// dropped datagram; [`TransportError::Closed`] ends the session.
#[derive(thiserror::Error, Debug)]
pub enum TransportError {
    /// The connection is permanently gone; the session should terminate.
    #[error("transport closed")]
    Closed,
    /// A transient error (e.g. datagram too large); treated as a drop.
    #[error("transport send failed: {0}")]
    Send(String),
    /// Underlying I/O error.
    #[error("transport io error: {0}")]
    Io(String),
}

/// An unreliable, unordered datagram transport.
#[async_trait::async_trait]
pub trait Transport: Send + Sync + 'static {
    /// Best-effort send of a single datagram. May silently drop. Returning
    /// [`TransportError::Closed`] signals the connection is gone.
    async fn send(&self, datagram: Bytes) -> Result<(), TransportError>;

    /// Await the next received datagram. Returns [`TransportError::Closed`] when
    /// the peer is gone and no more datagrams will arrive.
    async fn recv(&self) -> Result<Bytes, TransportError>;

    /// Largest datagram that can be sent in one piece. The protocol fragments
    /// instructions larger than this (fragmentation is TODO; for transports with
    /// no practical limit return [`usize::MAX`]).
    fn max_datagram_size(&self) -> usize {
        usize::MAX
    }
}
