//! Multi-threaded concurrency stress for the [`Driver`], intended to be run under
//! ThreadSanitizer (`-Zsanitizer=thread`). Unlike the other async tests, this one
//! uses a **multi-thread** tokio runtime and drives the Driver's shared-state
//! channels (the `mpsc` local-state queue and the `watch` remote-state cell) from
//! several threads at once — plus the lossy link's relay tasks — so TSan actually
//! has cross-thread interleavings to check. It also asserts the protocol still
//! converges under that concurrency.
//!
//! See `scripts/tsan.sh` / the CI `tsan` job for how it's run instrumented.

use std::sync::Arc;
use std::time::Duration;

use mish_ssp::clock::SystemClock;
use mish_ssp::core::SspConfig;
use mish_ssp::memory::{self, Impairments};
use mish_ssp::session::{Driver, Session, SessionHandle};
use mish_ssp::states::BytesState;

type Handle = SessionHandle<BytesState, BytesState>;

fn fast_cfg() -> SspConfig {
    SspConfig {
        rto: 40,
        ack_interval: 100,
        ack_delay: 5,
        send_interval_min: 2,
        ..Default::default()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_updates_and_reads_converge() {
    // A lossy link so the relay tasks (spawned onto the worker threads) are part
    // of the concurrent picture too.
    let imp = Impairments {
        loss: 0.15,
        min_delay_ms: 0,
        max_delay_ms: 4,
        seed: 0x5EED,
        ..Default::default()
    };
    let (ta, tb) = memory::pair_with(imp);
    let clock = Arc::new(SystemClock::new());
    let (da, ha) =
        Driver::<_, BytesState, BytesState>::with(Arc::new(ta), clock.clone(), fast_cfg());
    let (db, hb) = Driver::<_, BytesState, BytesState>::with(Arc::new(tb), clock, fast_cfg());
    da.spawn();
    db.spawn();

    // Several tasks hammer `set_local` on cloned handles concurrently (the handle
    // is Clone; its sender is shared across threads), while a reader watches the
    // remote state — exercising the channels from multiple worker threads.
    let mut writers = Vec::new();
    for w in 0..4u32 {
        let h: Handle = ha.clone();
        writers.push(tokio::spawn(async move {
            for i in 0..50u32 {
                h.set_local(BytesState::new(format!("w{w}-{i}").into_bytes()));
                if i % 8 == 0 {
                    tokio::task::yield_now().await;
                }
            }
        }));
    }
    let reader = {
        let mut h: Handle = hb.clone();
        tokio::spawn(async move {
            // Drain remote-state changes concurrently with the writers.
            for _ in 0..20 {
                if h.remote_changed().await.is_none() {
                    break;
                }
            }
        })
    };
    for w in writers {
        w.await.unwrap();
    }
    reader.await.unwrap();

    // After the concurrent churn, a final deterministic update must converge.
    ha.set_local(BytesState::new(b"FINAL".to_vec()));
    let mut hb_reader = hb.clone();
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if hb_reader.remote().as_slice() == b"FINAL" {
                return;
            }
            if hb_reader.remote_changed().await.is_none() {
                panic!("driver stopped before converging");
            }
        }
    })
    .await
    .expect("converges to the final state after concurrent churn");

    drop((ha, hb));
}
