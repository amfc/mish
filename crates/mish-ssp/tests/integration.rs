//! End-to-end async tests of the [`Driver`] / [`Session`] layer over the
//! in-memory [`Transport`], including a lossy/reordering link. Unlike the
//! virtual-time sim tests, these run on the real tokio runtime and exercise the
//! actual event loop, channels, and serialization.

use std::sync::Arc;
use std::time::Duration;

use mish_ssp::clock::SystemClock;
use mish_ssp::core::SspConfig;
use mish_ssp::memory::{self, Impairments};
use mish_ssp::session::{Driver, Session};
use mish_ssp::states::BytesState;
use mish_ssp::transport::Transport;

/// Snappy timing so real-time tests converge quickly.
fn fast_cfg() -> SspConfig {
    SspConfig {
        rto: 60,
        ack_interval: 250,
        ack_delay: 10,
        send_interval_min: 5,
        ..Default::default()
    }
}

type Handle = mish_ssp::session::SessionHandle<BytesState, BytesState>;

fn connect<TA, TB>(ta: TA, tb: TB) -> (Handle, Handle)
where
    TA: Transport,
    TB: Transport,
{
    let clock = Arc::new(SystemClock::new());
    let (da, ha) = Driver::<_, BytesState, BytesState>::with(Arc::new(ta), clock.clone(), fast_cfg());
    let (db, hb) = Driver::<_, BytesState, BytesState>::with(Arc::new(tb), clock, fast_cfg());
    da.spawn();
    db.spawn();
    (ha, hb)
}

#[tokio::test]
async fn clean_shutdown_closes_both_sides() {
    let (ta, tb) = memory::pair();
    let clock = Arc::new(SystemClock::new());
    let (da, ha) = Driver::<_, BytesState, BytesState>::with(Arc::new(ta), clock.clone(), fast_cfg());
    let (db, hb) = Driver::<_, BytesState, BytesState>::with(Arc::new(tb), clock, fast_cfg());
    let task_a = da.spawn();
    let task_b = db.spawn();

    // Establish the connection, then request a clean shutdown from A.
    ha.set_local(BytesState::new(b"hi".to_vec()));
    tokio::time::sleep(Duration::from_millis(100)).await;
    ha.shutdown();

    // The handshake mirrors to B; both drivers must terminate *promptly* — well
    // under the 5s grace deadline, proving it's the ack handshake, not a fallback
    // timeout. (Whichever exits first drops its transport, so the other may see a
    // Closed rather than a clean Ok — both are a closed session.)
    let both = async {
        let _ = task_a.await;
        let _ = task_b.await;
    };
    tokio::time::timeout(Duration::from_secs(2), both)
        .await
        .expect("shutdown handshake should close both drivers promptly");
    // Keep handles alive until here so local channels don't close early.
    drop((ha, hb));
}

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

#[tokio::test]
async fn lossless_one_way() {
    let (ta, tb) = memory::pair();
    let (ha, mut hb) = connect(ta, tb);

    ha.set_local(BytesState::new(b"hello from A".to_vec()));
    tokio::time::timeout(Duration::from_secs(5), await_state(&mut hb, b"hello from A"))
        .await
        .expect("converged");
}

#[tokio::test]
async fn lossless_two_way() {
    let (ta, tb) = memory::pair();
    let (mut ha, mut hb) = connect(ta, tb);

    ha.set_local(BytesState::new(b"payload A".to_vec()));
    hb.set_local(BytesState::new(b"payload B".to_vec()));

    tokio::time::timeout(Duration::from_secs(5), async {
        await_state(&mut hb, b"payload A").await;
        await_state(&mut ha, b"payload B").await;
    })
    .await
    .expect("both directions converged");
}

#[tokio::test]
async fn sequence_converges_to_latest() {
    let (ta, tb) = memory::pair();
    let (ha, mut hb) = connect(ta, tb);

    for i in 0..30u32 {
        ha.set_local(BytesState::new(format!("v{i}").into_bytes()));
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    tokio::time::timeout(Duration::from_secs(5), await_state(&mut hb, b"v29"))
        .await
        .expect("converged to latest");
}

#[tokio::test]
async fn converges_over_lossy_link() {
    let imp = Impairments {
        loss: 0.3,
        min_delay_ms: 1,
        max_delay_ms: 15,
        seed: 0xBADC0FFEE,
        ..Default::default()
    };
    let (ta, tb) = memory::pair_with(imp);
    let (ha, mut hb) = connect(ta, tb);

    ha.set_local(BytesState::new(b"reliable over unreliable".to_vec()));
    tokio::time::timeout(
        Duration::from_secs(15),
        await_state(&mut hb, b"reliable over unreliable"),
    )
    .await
    .expect("converged despite 30% loss");
}

#[tokio::test]
async fn closed_transport_ends_session() {
    let (ta, tb) = memory::pair();
    let clock = Arc::new(SystemClock::new());
    let (da, _ha) = Driver::<_, BytesState, BytesState>::with(Arc::new(ta), clock, fast_cfg());
    let task = da.spawn();
    // Drop the peer transport; the driver's recv should error with Closed.
    drop(tb);
    let result = tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .expect("driver should stop promptly");
    assert!(result.is_ok(), "task joined");
}
