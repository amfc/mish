//! Run the **real** QUIC stack ([`QuicTransport`](crate::QuicTransport)) over
//! [`turmoil`](https://docs.rs/turmoil)'s simulated network — deterministically.
//!
//! The wall-clock A/B harness (`mish-ssp`'s `bench-harness`) is the only place we
//! can see QUIC's own contribution (per-packet framing, ack scheduling, the real
//! RTT estimator) — the sans-IO `tail_probe` and the UDP `TurmoilUdpTransport`
//! both omit quinn. That made the bench the sole arbiter for transport-level
//! questions, at the cost of being slow and noisy. This module closes that gap:
//! it drives **quinn itself** over turmoil's controllable clock and fault model,
//! so QUIC-in-the-loop results become reproducible and instant.
//!
//! The trick is small because quinn's stock [`TokioRuntime`] already routes every
//! timer and time read through `tokio::time` (which turmoil controls) and spawns
//! via `tokio::spawn` (onto the turmoil host's runtime). The only piece quinn's
//! Tokio runtime can't provide under simulation is the socket — its
//! `wrap_udp_socket` wraps a real OS `std::net::UdpSocket`, which turmoil does not
//! intercept. So all we supply is a [`TurmoilUdpSocket`]: an [`AsyncUdpSocket`]
//! backed by [`turmoil::net::UdpSocket`]. Build the endpoint with
//! [`Endpoint::new_with_abstract_socket`] + `TokioRuntime` and the rest of the
//! stack runs unchanged.
//!
//! Network latency / loss / reordering come from turmoil's `Builder`, so (unlike
//! [`crate::lossy`]) the socket injects no faults of its own.

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, Endpoint, EndpointConfig, TokioRuntime, UdpPoller};
use rustls::pki_types::CertificateDer;
use tokio::sync::mpsc;
use turmoil::net::UdpSocket;

use crate::config;
use crate::transport::QuicError;

/// Receive buffer for the pump task (one datagram at a time).
const RECV_BUF: usize = 64 * 1024;

/// An [`AsyncUdpSocket`] over turmoil's simulated UDP.
///
/// turmoil's `UdpSocket` only exposes async / `try_*` methods, not the poll-based
/// recv quinn wants, so a background pump task drives `recv_from` and forwards
/// datagrams over an unbounded channel that [`poll_recv`](Self::poll_recv) drains.
/// Sends go straight through `try_send_to` (turmoil's send queue doesn't block).
struct TurmoilUdpSocket {
    socket: Arc<UdpSocket>,
    local: SocketAddr,
    rx: Mutex<mpsc::UnboundedReceiver<(Vec<u8>, SocketAddr)>>,
}

impl fmt::Debug for TurmoilUdpSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TurmoilUdpSocket").field("local", &self.local).finish()
    }
}

impl TurmoilUdpSocket {
    /// Bind a simulated socket and spawn its receive pump. Must be called inside
    /// a turmoil host (so the pump's `tokio::spawn` lands on the host runtime).
    async fn bind(addr: SocketAddr) -> io::Result<Arc<Self>> {
        let socket = Arc::new(UdpSocket::bind(addr).await?);
        let local = socket.local_addr()?;
        let (tx, rx) = mpsc::unbounded_channel();
        let pump = socket.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; RECV_BUF];
            loop {
                match pump.recv_from(&mut buf).await {
                    Ok((n, from)) => {
                        // Channel closed ⇒ socket dropped; stop pumping.
                        if tx.send((buf[..n].to_vec(), from)).is_err() {
                            return;
                        }
                    }
                    Err(_) => return, // socket gone
                }
            }
        });
        Ok(Arc::new(Self {
            socket,
            local,
            rx: Mutex::new(rx),
        }))
    }
}

/// A [`UdpPoller`] that is always writable: turmoil's `try_send_to` enqueues
/// without blocking, so a send is never deferred.
#[derive(Debug)]
struct AlwaysWritable;

impl UdpPoller for AlwaysWritable {
    fn poll_writable(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncUdpSocket for TurmoilUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(AlwaysWritable)
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        // One datagram per transmit (we report a single segment), so no GSO split.
        match self.socket.try_send_to(transmit.contents, transmit.destination) {
            Ok(_) => Ok(()),
            // turmoil shouldn't block, but treat it as a drop if it ever does —
            // the SSP layer heals via the next re-diff, exactly as on a real link.
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut rx = self.rx.lock().unwrap();
        match rx.poll_recv(cx) {
            Poll::Ready(Some((data, from))) => {
                let n = data.len().min(bufs[0].len());
                bufs[0][..n].copy_from_slice(&data[..n]);
                meta[0] = RecvMeta {
                    addr: from,
                    len: n,
                    stride: n,
                    ecn: None,
                    dst_ip: None,
                };
                Poll::Ready(Ok(1))
            }
            // Pump gone (teardown): never resolve. The sim ends via its own budget.
            Poll::Ready(None) => Poll::Pending,
            Poll::Pending => Poll::Pending,
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }

    fn may_fragment(&self) -> bool {
        // Report "may fragment" so quinn disables DPLPMTUD and stays at the safe
        // 1200-byte initial MTU — turmoil delivers datagrams whole, and this avoids
        // MTU-probe traffic perturbing the timing we're measuring.
        true
    }
}

/// Build a datagram-enabled QUIC **server** endpoint over turmoil's UDP, bound to
/// `addr`. Returns the endpoint and the self-signed cert clients should trust.
/// Call inside a turmoil host.
pub async fn turmoil_server_endpoint(
    addr: SocketAddr,
) -> Result<(Endpoint, CertificateDer<'static>), QuicError> {
    let (server_config, cert) = config::self_signed_server_config();
    let socket = TurmoilUdpSocket::bind(addr).await?;
    let endpoint = Endpoint::new_with_abstract_socket(
        EndpointConfig::default(),
        Some(server_config),
        socket,
        Arc::new(TokioRuntime),
    )?;
    Ok((endpoint, cert))
}

/// Build a QUIC **client** endpoint over turmoil's UDP, bound to `addr`, that
/// accepts any server certificate (testing only — avoids threading the server's
/// self-signed cert across turmoil hosts). The returned endpoint's default config
/// is set, so [`crate::connect`] works against it. Call inside a turmoil host.
pub async fn turmoil_insecure_client_endpoint(addr: SocketAddr) -> Result<Endpoint, QuicError> {
    let socket = TurmoilUdpSocket::bind(addr).await?;
    let mut endpoint = Endpoint::new_with_abstract_socket(
        EndpointConfig::default(),
        None,
        socket,
        Arc::new(TokioRuntime),
    )?;
    endpoint.set_default_client_config(config::insecure_client_config());
    Ok(endpoint)
}
