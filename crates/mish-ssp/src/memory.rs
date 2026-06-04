//! In-memory [`Transport`] for local testing.
//!
//! [`pair`] yields two connected endpoints backed by channels — a perfect
//! (lossless, ordered) link. [`pair_with`] adds configurable, *deterministic*
//! impairments (loss, latency, reordering) driven by a seeded RNG, so failure
//! scenarios are reproducible.
//!
//! For exhaustive, virtual-time fault injection prefer the sans-IO core with a
//! synchronous simulator (see the `sim` test). This async transport is for
//! end-to-end tests of the [`crate::session`] driver over real tokio time.

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use tokio::sync::mpsc;

use crate::transport::{Transport, TransportError};

/// One endpoint of an in-memory link.
pub struct MemoryTransport {
    outgoing: mpsc::UnboundedSender<Bytes>,
    incoming: tokio::sync::Mutex<mpsc::UnboundedReceiver<Bytes>>,
    max_dgram: usize,
}

#[async_trait::async_trait]
impl Transport for MemoryTransport {
    async fn send(&self, datagram: Bytes) -> Result<(), TransportError> {
        if datagram.len() > self.max_dgram {
            // Mirror a real datagram transport: oversize sends fail (and are
            // treated by the protocol as a drop). Fragmentation is the fix.
            return Err(TransportError::Send(format!(
                "datagram {} > max {}",
                datagram.len(),
                self.max_dgram
            )));
        }
        self.outgoing
            .send(datagram)
            .map_err(|_| TransportError::Closed)
    }

    async fn recv(&self) -> Result<Bytes, TransportError> {
        let mut rx = self.incoming.lock().await;
        rx.recv().await.ok_or(TransportError::Closed)
    }

    fn max_datagram_size(&self) -> usize {
        self.max_dgram
    }
}

/// Create a pair of connected, lossless, ordered in-memory transports.
pub fn pair() -> (MemoryTransport, MemoryTransport) {
    let (a_tx, b_rx) = mpsc::unbounded_channel();
    let (b_tx, a_rx) = mpsc::unbounded_channel();
    let a = MemoryTransport {
        outgoing: a_tx,
        incoming: tokio::sync::Mutex::new(a_rx),
        max_dgram: usize::MAX,
    };
    let b = MemoryTransport {
        outgoing: b_tx,
        incoming: tokio::sync::Mutex::new(b_rx),
        max_dgram: usize::MAX,
    };
    (a, b)
}

/// Deterministic link impairments for [`pair_with`].
#[derive(Clone, Copy, Debug)]
pub struct Impairments {
    /// Probability in `[0.0, 1.0]` that a datagram is dropped.
    pub loss: f64,
    /// Minimum one-way delay applied to delivered datagrams (ms).
    pub min_delay_ms: u64,
    /// Maximum one-way delay (ms). Delay is uniform in `[min, max]`; variability
    /// reorders datagrams.
    pub max_delay_ms: u64,
    /// Seed for the deterministic RNG. Same seed ⇒ same drop/delay sequence.
    pub seed: u64,
    /// Largest deliverable datagram; larger sends fail.
    pub max_dgram: usize,
}

impl Default for Impairments {
    fn default() -> Self {
        Self {
            loss: 0.0,
            min_delay_ms: 0,
            max_delay_ms: 0,
            seed: 0x9E3779B97F4A7C15,
            max_dgram: usize::MAX,
        }
    }
}

/// Deterministic xorshift64* RNG — reproducible impairments without pulling in
/// an RNG crate.
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
    /// Uniform float in `[0, 1)`.
    fn next_f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }
    fn delay_in(&mut self, lo: u64, hi: u64) -> u64 {
        if hi <= lo {
            lo
        } else {
            lo + self.next_u64() % (hi - lo + 1)
        }
    }
}

/// Create a pair of in-memory transports connected through a lossy/latent link.
///
/// Each direction gets an independent relay task that drops and delays datagrams
/// per `imp`. The relays must run on a tokio runtime.
pub fn pair_with(imp: Impairments) -> (MemoryTransport, MemoryTransport) {
    let a = build_endpoint(imp, imp.seed);
    let b = build_endpoint(imp, imp.seed ^ 0xD1B54A32D192ED03);
    // Cross-connect: a's relayed output feeds b's input and vice versa.
    let a_out = a.relay_to_peer;
    let b_out = b.relay_to_peer;
    (
        MemoryTransport {
            outgoing: a_out,
            incoming: tokio::sync::Mutex::new(b.from_peer),
            max_dgram: imp.max_dgram,
        },
        MemoryTransport {
            outgoing: b_out,
            incoming: tokio::sync::Mutex::new(a.from_peer),
            max_dgram: imp.max_dgram,
        },
    )
}

struct Endpoint {
    /// Where the application sends; consumed by the relay.
    relay_to_peer: mpsc::UnboundedSender<Bytes>,
    /// Where relayed datagrams from the peer arrive.
    from_peer: mpsc::UnboundedReceiver<Bytes>,
}

/// Build one direction: app → relay (loss/delay) → peer's inbox.
fn build_endpoint(imp: Impairments, seed: u64) -> Endpoint {
    let (app_tx, mut app_rx) = mpsc::unbounded_channel::<Bytes>();
    let (peer_tx, peer_rx) = mpsc::unbounded_channel::<Bytes>();
    let rng = Arc::new(Mutex::new(Rng(seed | 1)));

    tokio::spawn(async move {
        while let Some(dgram) = app_rx.recv().await {
            let (drop, delay) = {
                let mut r = rng.lock().unwrap();
                (
                    r.next_f64() < imp.loss,
                    r.delay_in(imp.min_delay_ms, imp.max_delay_ms),
                )
            };
            if drop {
                continue;
            }
            let peer_tx = peer_tx.clone();
            if delay == 0 {
                let _ = peer_tx.send(dgram);
            } else {
                // Independent delay per datagram naturally reorders them.
                tokio::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                    let _ = peer_tx.send(dgram);
                });
            }
        }
    });

    Endpoint {
        relay_to_peer: app_tx,
        from_peer: peer_rx,
    }
}
