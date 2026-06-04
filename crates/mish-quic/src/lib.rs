//! # mish-quic
//!
//! A [`mish_ssp::Transport`] implemented over **QUIC unreliable datagrams**
//! (via [Quinn](https://github.com/quinn-rs/quinn)).
//!
//! QUIC provides the parts mosh built by hand — authenticated encryption,
//! congestion control, and **connection migration** (roaming across IP/port
//! changes) — while its unreliable datagram extension gives us exactly the
//! best-effort delivery the State Synchronization Protocol expects. SSP, not
//! QUIC, provides reliability: a dropped datagram is healed by the next one
//! re-diffing from an earlier state.
//!
//! ## Layout
//!
//! * [`config`] — datagram-enabled QUIC/TLS configs + self-signed/insecure certs.
//! * [`transport`] — [`transport::QuicTransport`] and endpoint helpers
//!   ([`transport::connect`], [`transport::accept`], …).
//! * [`lossy`] — a deterministic loss-injecting socket to test SSP recovery over
//!   a real QUIC connection.

pub mod config;
pub mod lossy;
pub mod transport;

pub use transport::{
    accept, client_endpoint, connect, insecure_client_endpoint, loopback_client, loopback_server,
    server_endpoint, QuicError, QuicTransport,
};
