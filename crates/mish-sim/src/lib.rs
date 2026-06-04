//! Deterministic network-simulation support for mish, built on
//! [`turmoil`](https://docs.rs/turmoil).
//!
//! turmoil runs many "hosts" on one simulated network with a controllable
//! clock, latency, packet loss, and partitions — a FoundationDB-style
//! deterministic distributed-systems test. This crate provides
//! [`TurmoilUdpTransport`], a [`mish_ssp::Transport`] over `turmoil`'s simulated
//! UDP, so the *real* async SSP [`mish_ssp::session::Driver`] can run unchanged
//! inside a simulation and be subjected to reproducible network faults.
//!
//! The SSP timers must follow simulated time, so always drive the session with
//! a [`mish_ssp::TokioClock`] (which reads `tokio::time`, the clock turmoil
//! controls) rather than the wall-clock [`mish_ssp::SystemClock`].

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bytes::Bytes;
use mish_ssp::transport::{Transport, TransportError};
use turmoil::net::UdpSocket;

/// Largest datagram the simulated UDP transport will send in one piece. Chosen
/// small enough to exercise the fragmentation/reassembly path under simulation.
pub const SIM_MAX_DATAGRAM: usize = 1200;

/// A [`Transport`] over turmoil's simulated UDP, for a single point-to-point
/// SSP association.
///
/// The peer address is fixed for a client (the server it dialed) and learned
/// on first receipt for a server (the client's source address). Re-learning the
/// peer on each receive also mirrors connection migration: if the client's
/// source address changes, the server follows it.
pub struct TurmoilUdpTransport {
    socket: Arc<UdpSocket>,
    peer: Mutex<Option<SocketAddr>>,
    max_datagram: usize,
}

impl TurmoilUdpTransport {
    /// Wrap an existing simulated socket. If `peer` is known (client side), sends
    /// go there immediately; otherwise (server side) it is learned on first recv.
    pub fn new(socket: UdpSocket, peer: Option<SocketAddr>) -> Self {
        Self {
            socket: Arc::new(socket),
            peer: Mutex::new(peer),
            max_datagram: SIM_MAX_DATAGRAM,
        }
    }

    /// Bind a server transport on `addr` (peer learned from the first datagram).
    pub async fn bind_server(addr: SocketAddr) -> Result<Self, TransportError> {
        let socket = UdpSocket::bind(addr)
            .await
            .map_err(|e| TransportError::Io(e.to_string()))?;
        Ok(Self::new(socket, None))
    }

    /// Bind a client transport on `local` targeting `server`.
    pub async fn connect(local: SocketAddr, server: SocketAddr) -> Result<Self, TransportError> {
        let socket = UdpSocket::bind(local)
            .await
            .map_err(|e| TransportError::Io(e.to_string()))?;
        Ok(Self::new(socket, Some(server)))
    }
}

#[async_trait]
impl Transport for TurmoilUdpTransport {
    async fn send(&self, datagram: Bytes) -> Result<(), TransportError> {
        let peer = *self.peer.lock().unwrap();
        let Some(peer) = peer else {
            // Don't know where to send yet (no datagram received). The SSP layer
            // treats this as a drop and retries.
            return Ok(());
        };
        match self.socket.send_to(&datagram, peer).await {
            Ok(_) => Ok(()),
            Err(e) => Err(TransportError::Send(e.to_string())),
        }
    }

    async fn recv(&self) -> Result<Bytes, TransportError> {
        let mut buf = vec![0u8; 65536];
        let (n, from) = self
            .socket
            .recv_from(&mut buf)
            .await
            .map_err(|_| TransportError::Closed)?;
        *self.peer.lock().unwrap() = Some(from);
        buf.truncate(n);
        Ok(Bytes::from(buf))
    }

    fn max_datagram_size(&self) -> usize {
        self.max_datagram
    }
}
