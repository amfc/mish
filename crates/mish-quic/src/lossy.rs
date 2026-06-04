//! A loss-injecting [`AsyncUdpSocket`] wrapper, for testing that the SSP layer
//! heals datagram loss over a *real* QUIC connection.
//!
//! QUIC reliably retransmits its handshake and control frames, but **not**
//! datagram frames — that's exactly the contract mish relies on. By dropping
//! egress UDP datagrams with a fixed probability (deterministic, seeded), we can
//! prove end-to-end that a lossy QUIC link still converges, with the recovery
//! coming entirely from SSP re-diffing rather than from QUIC.
//!
//! Drops are applied on send. Because `max_transmit_segments` is forced to 1,
//! each `try_send` is a single UDP datagram, so the drop probability is per
//! datagram.

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, Endpoint, EndpointConfig, Runtime, ServerConfig, TokioRuntime, UdpPoller};
use rustls::pki_types::CertificateDer;

use crate::config;
use crate::transport::QuicError;

struct Rng(u64);
impl Rng {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
    fn chance(&mut self, p: f64) -> bool {
        ((self.next_u64() >> 11) as f64 / (1u64 << 53) as f64) < p
    }
}

/// Wraps a real socket and drops a fraction of outgoing datagrams.
struct LossyUdpSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    loss: f64,
    rng: Mutex<Rng>,
}

impl fmt::Debug for LossyUdpSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LossyUdpSocket")
            .field("loss", &self.loss)
            .finish()
    }
}

impl AsyncUdpSocket for LossyUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        if self.loss > 0.0 && self.rng.lock().unwrap().chance(self.loss) {
            // Pretend the datagram went out; it's silently lost on the wire.
            return Ok(());
        }
        self.inner.try_send(transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.inner.poll_recv(cx, bufs, meta)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        // One UDP datagram per try_send ⇒ clean per-datagram loss.
        1
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

fn lossy_socket(bind: SocketAddr, loss: f64, seed: u64) -> io::Result<Arc<dyn AsyncUdpSocket>> {
    let std_sock = std::net::UdpSocket::bind(bind)?;
    let inner = TokioRuntime.wrap_udp_socket(std_sock)?;
    Ok(Arc::new(LossyUdpSocket {
        inner,
        loss,
        rng: Mutex::new(Rng(seed | 1)),
    }))
}

fn runtime() -> Arc<dyn Runtime> {
    Arc::new(TokioRuntime)
}

/// A server endpoint whose outbound datagrams are dropped with probability
/// `loss`. Returns the endpoint and the cert to trust.
pub fn lossy_server_endpoint(
    bind: SocketAddr,
    loss: f64,
    seed: u64,
) -> Result<(Endpoint, CertificateDer<'static>), QuicError> {
    let (server_config, cert): (ServerConfig, _) = config::self_signed_server_config();
    let socket = lossy_socket(bind, loss, seed)?;
    let endpoint = Endpoint::new_with_abstract_socket(
        EndpointConfig::default(),
        Some(server_config),
        socket,
        runtime(),
    )?;
    Ok((endpoint, cert))
}

/// A client endpoint whose outbound datagrams are dropped with probability
/// `loss` (accepts any server cert — testing only).
pub fn lossy_insecure_client_endpoint(
    bind: SocketAddr,
    loss: f64,
    seed: u64,
) -> Result<Endpoint, QuicError> {
    let socket = lossy_socket(bind, loss, seed)?;
    let mut endpoint = Endpoint::new_with_abstract_socket(
        EndpointConfig::default(),
        None,
        socket,
        runtime(),
    )?;
    endpoint.set_default_client_config(config::insecure_client_config());
    Ok(endpoint)
}
