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
use quinn::{
    AsyncUdpSocket, Endpoint, EndpointConfig, Runtime, ServerConfig, TokioRuntime, UdpPoller,
};
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

/// Per-datagram fault injection rates (all in `[0, 1]`).
#[derive(Clone, Copy, Default)]
pub struct Faults {
    /// Probability the datagram is silently dropped.
    pub loss: f64,
    /// Probability a *duplicate* is also sent (QUIC's packet-number replay
    /// window must drop it at the receiver — no double-apply).
    pub dup: f64,
    /// Probability a byte is flipped before sending (QUIC's AEAD must reject the
    /// tampered packet — it never reaches the application).
    pub corrupt: f64,
}

/// Wraps a real socket and injects per-datagram faults (loss/dup/corruption).
struct LossyUdpSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    faults: Faults,
    rng: Mutex<Rng>,
}

impl fmt::Debug for LossyUdpSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LossyUdpSocket")
            .field("loss", &self.faults.loss)
            .field("dup", &self.faults.dup)
            .field("corrupt", &self.faults.corrupt)
            .finish()
    }
}

impl AsyncUdpSocket for LossyUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        // Roll all decisions under the lock, then do I/O without holding it.
        let (drop, corrupt_at, dup) = {
            let mut rng = self.rng.lock().unwrap();
            let drop = self.faults.loss > 0.0 && rng.chance(self.faults.loss);
            let corrupt = self.faults.corrupt > 0.0
                && !transmit.contents.is_empty()
                && rng.chance(self.faults.corrupt);
            let corrupt_at = corrupt.then(|| (rng.next_u64() as usize) % transmit.contents.len());
            let dup = self.faults.dup > 0.0 && rng.chance(self.faults.dup);
            (drop, corrupt_at, dup)
        };
        if drop {
            // Pretend the datagram went out; it's silently lost on the wire.
            return Ok(());
        }
        if let Some(i) = corrupt_at {
            // Flip a byte; QUIC's AEAD rejects the packet, so it's effectively
            // lost (the SSP layer heals via the next, uncorrupted frame).
            let mut buf = transmit.contents.to_vec();
            buf[i] ^= 0xff;
            let mangled = Transmit {
                destination: transmit.destination,
                ecn: transmit.ecn,
                contents: &buf,
                segment_size: transmit.segment_size,
                src_ip: transmit.src_ip,
            };
            return self.inner.try_send(&mangled);
        }
        let r = self.inner.try_send(transmit);
        if dup {
            let _ = self.inner.try_send(transmit);
        }
        r
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

fn faulty_socket(
    bind: SocketAddr,
    faults: Faults,
    seed: u64,
) -> io::Result<Arc<dyn AsyncUdpSocket>> {
    let std_sock = std::net::UdpSocket::bind(bind)?;
    let inner = TokioRuntime.wrap_udp_socket(std_sock)?;
    Ok(Arc::new(LossyUdpSocket {
        inner,
        faults,
        rng: Mutex::new(Rng(seed | 1)),
    }))
}

fn lossy_socket(bind: SocketAddr, loss: f64, seed: u64) -> io::Result<Arc<dyn AsyncUdpSocket>> {
    faulty_socket(
        bind,
        Faults {
            loss,
            ..Default::default()
        },
        seed,
    )
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
    let mut endpoint =
        Endpoint::new_with_abstract_socket(EndpointConfig::default(), None, socket, runtime())?;
    endpoint.set_default_client_config(config::insecure_client_config());
    Ok(endpoint)
}

/// A server endpoint whose outbound datagrams suffer `faults` (loss/dup/
/// corruption). Returns the endpoint and the cert to trust.
pub fn faulty_server_endpoint(
    bind: SocketAddr,
    faults: Faults,
    seed: u64,
) -> Result<(Endpoint, CertificateDer<'static>), QuicError> {
    let (server_config, cert): (ServerConfig, _) = config::self_signed_server_config();
    let socket = faulty_socket(bind, faults, seed)?;
    let endpoint = Endpoint::new_with_abstract_socket(
        EndpointConfig::default(),
        Some(server_config),
        socket,
        runtime(),
    )?;
    Ok((endpoint, cert))
}

/// An insecure client endpoint whose outbound datagrams suffer `faults`.
pub fn faulty_insecure_client_endpoint(
    bind: SocketAddr,
    faults: Faults,
    seed: u64,
) -> Result<Endpoint, QuicError> {
    let socket = faulty_socket(bind, faults, seed)?;
    let mut endpoint =
        Endpoint::new_with_abstract_socket(EndpointConfig::default(), None, socket, runtime())?;
    endpoint.set_default_client_config(config::insecure_client_config());
    Ok(endpoint)
}
