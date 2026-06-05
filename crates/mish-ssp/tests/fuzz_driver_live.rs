//! Live-Driver garbage-flood fuzz: the *async* counterpart to the deterministic
//! core-level `fuzz_hostile` tests.
//!
//! `fuzz_hostile` proves the sans-IO core is safe against adversarial input;
//! this proves the real [`Driver`] event loop — its `recv`/defragment/decode/
//! tick path, channels, and timers — survives a sustained flood of random
//! datagrams interleaved with honest peer traffic, on a real tokio runtime,
//! without panicking, wedging, or failing to converge.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use mish_ssp::clock::SystemClock;
use mish_ssp::core::SspConfig;
use mish_ssp::memory::{self, MemoryTransport};
use mish_ssp::session::{Driver, Session, SessionHandle};
use mish_ssp::states::BytesState;
use mish_ssp::transport::{Transport, TransportError};

fn fast_cfg() -> SspConfig {
    SspConfig {
        rto: 60,
        ack_interval: 250,
        ack_delay: 10,
        send_interval_min: 5,
        ..Default::default()
    }
}

/// Deterministic xorshift64* — reproducible garbage from a seed.
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
}

/// A [`Transport`] that wraps an honest in-memory endpoint and floods the
/// receiver with garbage: every other `recv` yields a random datagram (paced by
/// 1ms so it's a flood, not a pure busy-spin) instead of waiting for the peer.
/// Honest datagrams still arrive on the interleaved recvs, so a correct protocol
/// must converge regardless.
struct NoisyTransport {
    inner: MemoryTransport,
    rng: Mutex<Rng>,
    counter: AtomicU64,
}

impl NoisyTransport {
    fn new(inner: MemoryTransport, seed: u64) -> Self {
        Self {
            inner,
            rng: Mutex::new(Rng(seed | 1)),
            counter: AtomicU64::new(0),
        }
    }

    fn garbage(&self) -> Bytes {
        let mut r = self.rng.lock().unwrap();
        // Mix in lengths around the fragment-header boundary and the empty
        // datagram, so the defragmenter's header parsing is exercised too.
        let len = match r.next_u64() % 8 {
            0 => 0,
            1 => 1,
            2 => (r.next_u64() % 8) as usize,
            _ => (r.next_u64() % 1400) as usize,
        };
        let mut buf = vec![0u8; len];
        for b in buf.iter_mut() {
            *b = r.next_u64() as u8;
        }
        Bytes::from(buf)
    }
}

#[async_trait::async_trait]
impl Transport for NoisyTransport {
    async fn send(&self, datagram: Bytes) -> Result<(), TransportError> {
        self.inner.send(datagram).await
    }

    async fn recv(&self) -> Result<Bytes, TransportError> {
        let n = self.counter.fetch_add(1, Ordering::SeqCst);
        if n % 2 == 1 {
            tokio::time::sleep(Duration::from_millis(1)).await;
            return Ok(self.garbage());
        }
        self.inner.recv().await
    }

    fn max_datagram_size(&self) -> usize {
        self.inner.max_datagram_size()
    }
}

type Handle = SessionHandle<BytesState, BytesState>;

async fn await_state(handle: &mut Handle, want: &[u8]) {
    if handle.remote().as_slice() == want {
        return;
    }
    while let Some(state) = handle.remote_changed().await {
        if state.as_slice() == want {
            return;
        }
    }
    panic!("session ended before reaching expected state");
}

/// Honest sender A, garbage-flooded receiver B: B must still converge to A's
/// state across many garbage seeds.
#[tokio::test]
async fn converges_with_garbage_flooded_receiver() {
    for seed in 0..8u64 {
        let (ta, tb) = memory::pair();
        let noisy_b = NoisyTransport::new(tb, seed.wrapping_mul(0x9E3779B97F4A7C15));
        let clock = Arc::new(SystemClock::new());
        let (da, ha) =
            Driver::<_, BytesState, BytesState>::with(Arc::new(ta), clock.clone(), fast_cfg());
        let (db, mut hb) =
            Driver::<_, BytesState, BytesState>::with(Arc::new(noisy_b), clock, fast_cfg());
        da.spawn();
        db.spawn();

        ha.set_local(BytesState::new(b"hello through the noise".to_vec()));
        tokio::time::timeout(
            Duration::from_secs(15),
            await_state(&mut hb, b"hello through the noise"),
        )
        .await
        .unwrap_or_else(|_| panic!("seed {seed}: must converge despite garbage flood"));
        drop(ha);
    }
}

/// Both endpoints flooded, two-way exchange: neither direction may be derailed.
#[tokio::test]
async fn two_way_converges_with_both_endpoints_flooded() {
    let (ta, tb) = memory::pair();
    let noisy_a = NoisyTransport::new(ta, 0xA11CE);
    let noisy_b = NoisyTransport::new(tb, 0xB0B);
    let clock = Arc::new(SystemClock::new());
    let (da, mut ha) =
        Driver::<_, BytesState, BytesState>::with(Arc::new(noisy_a), clock.clone(), fast_cfg());
    let (db, mut hb) =
        Driver::<_, BytesState, BytesState>::with(Arc::new(noisy_b), clock, fast_cfg());
    da.spawn();
    db.spawn();

    ha.set_local(BytesState::new(b"payload A".to_vec()));
    hb.set_local(BytesState::new(b"payload B".to_vec()));

    tokio::time::timeout(Duration::from_secs(20), async {
        await_state(&mut hb, b"payload A").await;
        await_state(&mut ha, b"payload B").await;
    })
    .await
    .expect("both directions converge despite mutual garbage floods");
}

/// A stream of updates through the flood still converges to the latest state.
#[tokio::test]
async fn latest_wins_under_garbage_flood() {
    let (ta, tb) = memory::pair();
    let noisy_b = NoisyTransport::new(tb, 0xDEADBEEF);
    let clock = Arc::new(SystemClock::new());
    let (da, ha) =
        Driver::<_, BytesState, BytesState>::with(Arc::new(ta), clock.clone(), fast_cfg());
    let (db, mut hb) =
        Driver::<_, BytesState, BytesState>::with(Arc::new(noisy_b), clock, fast_cfg());
    da.spawn();
    db.spawn();

    for i in 0..40u32 {
        ha.set_local(BytesState::new(format!("v{i}").into_bytes()));
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    tokio::time::timeout(Duration::from_secs(15), await_state(&mut hb, b"v39"))
        .await
        .expect("converges to latest despite garbage flood");
    drop(ha);
}
