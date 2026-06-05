//! Regression: sustained **client→server** datagram delivery over the authenticated
//! transport across two endpoints (the real binary's topology), while the server
//! is simultaneously sending its own datagrams the other way. Reproduces a stall
//! where only the first couple of client→server datagrams arrive and the rest are
//! silently never delivered.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use mish_quic::transport;
use mish_ssp::transport::Transport;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sustained_client_to_server_datagrams() {
    let (server_ep, addr, auth) = transport::loopback_authenticated_server().unwrap();

    let got = Arc::new(AtomicU64::new(0));
    let got2 = got.clone();
    let server = tokio::spawn(async move {
        let t = transport::accept(&server_ep).await.expect("accept");
        let t = Arc::new(t);
        // Server also pushes datagrams toward the client (mimics screen updates),
        // so both directions are active — as in a live session.
        let ts = t.clone();
        tokio::spawn(async move {
            for _ in 0..200 {
                let _ = ts.send(Bytes::from_static(b"screen-update")).await;
                tokio::time::sleep(Duration::from_millis(30)).await;
            }
        });
        while let Ok(b) = t.recv().await {
            if b.as_ref().starts_with(b"key") {
                got2.fetch_add(1, Ordering::Relaxed);
            }
        }
    });

    let client_ep = transport::authenticated_client_endpoint(
        "127.0.0.1:0".parse().unwrap(),
        &auth.server_cert_der,
        &auth.client_cert_der,
        &auth.client_key_der,
    )
    .unwrap();
    let t = transport::connect(&client_ep, addr, "localhost")
        .await
        .expect("connect");

    // Initial datagram (like the resize), settle, then a stream of keystrokes
    // spaced out over time — the exact cadence that stalled in the harness.
    let _ = t.send(Bytes::from_static(b"resize")).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    const N: u64 = 20;
    for i in 0..N {
        let _ = t.send(Bytes::from(format!("key{i}"))).await;
        tokio::time::sleep(Duration::from_millis(60)).await;
    }

    // Give them time to drain.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let n = got.load(Ordering::Relaxed);
    server.abort();
    assert_eq!(
        n, N,
        "server should have received all {N} client→server keystroke datagrams, got {n}"
    );
}
