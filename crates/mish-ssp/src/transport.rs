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
use std::time::Duration;

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

    /// The transport's own smoothed round-trip-time estimate, if it keeps one.
    /// QUIC does, and unlike our app-layer timestamp sampler it is robust to
    /// reordering and retransmit ambiguity (RFC 9002: packet numbers strictly
    /// increase and are never reused, and reordered acks don't pollute the
    /// estimate). The SSP core prefers this over its internal estimator to derive
    /// its send cadence and RTO — which keeps the RTO from ballooning under burst
    /// reordering, the BRUTAL keyboard-tail fix (see `PERFORMANCE.md`). `None`
    /// (the default) ⇒ no transport estimate; the core falls back to its own.
    fn rtt(&self) -> Option<Duration> {
        None
    }

    /// Cumulative `(sent, lost)` packet counts since the connection opened, if
    /// the transport tracks them. QUIC does (RFC 9002 loss detection); the client
    /// samples the deltas to show a rolling loss rate in its status bar. These are
    /// QUIC-packet-level counters, not application datagrams, but they are the
    /// transport's own honest view of how lossy the path is. `None` (the default)
    /// ⇒ the transport keeps no such estimate (e.g. the in-memory test transport).
    fn loss_counters(&self) -> Option<(u64, u64)> {
        None
    }

    /// The peer's current address, if the transport has one. Changes when a QUIC
    /// connection migrates (roaming), so the status bar can show where the session
    /// is currently anchored. `None` (the default) ⇒ no addressable peer.
    fn peer_addr(&self) -> Option<String> {
        None
    }
}
