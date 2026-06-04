//! End-to-end tests of the SSP [`Driver`] running over a real QUIC connection.
//!
//! These spin up actual Quinn endpoints on loopback UDP sockets and drive the
//! full stack: `BytesState` → `SspCore` → `Driver` → `QuicTransport` → QUIC
//! datagrams → and back. They cover the clean case, recovery over a lossy link
//! (where QUIC does *not* retransmit datagrams — SSP does the healing), and
//! connection migration (roaming).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use mish_ssp::clock::{Clock, SystemClock};
use mish_ssp::core::SspConfig;
use mish_ssp::session::{Driver, Session, SessionHandle};
use mish_ssp::states::BytesState;

use mish_quic::lossy;
use mish_quic::transport::{self, QuicTransport};
use tokio::sync::oneshot;

type Handle = SessionHandle<BytesState, BytesState>;

fn fast_cfg() -> SspConfig {
    SspConfig {
        rto: 80,
        ack_interval: 250,
        ack_delay: 10,
        send_interval_min: 5,
        ..Default::default()
    }
}

fn clock() -> Arc<dyn Clock> {
    Arc::new(SystemClock::new())
}

/// Spawn a driver for an accepted/connected transport and return its handle.
fn spawn_driver(t: QuicTransport, clock: Arc<dyn Clock>) -> Handle {
    let (driver, handle) =
        Driver::<_, BytesState, BytesState>::with(Arc::new(t), clock, fast_cfg());
    driver.spawn();
    handle
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
async fn quic_two_way_sync() {
    let (server_ep, addr, _cert) = transport::loopback_server().unwrap();
    let clk = clock();

    // Server side: accept one connection, run a driver, hand back the handle.
    let (tx, rx) = oneshot::channel::<Handle>();
    let srv_clk = clk.clone();
    let server_task = tokio::spawn(async move {
        let t = transport::accept(&server_ep).await.unwrap();
        let handle = spawn_driver(t, srv_clk);
        tx.send(handle).ok();
        // Keep the endpoint alive for the duration of the test.
        std::future::pending::<()>().await;
    });

    // Client side.
    let client_ep = transport::loopback_client().unwrap();
    let t = transport::connect(&client_ep, addr, "localhost")
        .await
        .unwrap();
    let mut client = spawn_driver(t, clk);
    let mut server = rx.await.unwrap();

    client.set_local(BytesState::new(b"hi from client".to_vec()));
    server.set_local(BytesState::new(b"hi from server".to_vec()));

    tokio::time::timeout(Duration::from_secs(10), async {
        await_state(&mut server, b"hi from client").await;
        await_state(&mut client, b"hi from server").await;
    })
    .await
    .expect("converged over QUIC");

    server_task.abort();
}

#[tokio::test]
async fn quic_recovers_from_datagram_loss() {
    // 25% of UDP datagrams are dropped on both sides. QUIC retransmits its
    // handshake but NOT datagram frames, so all data recovery is SSP's doing.
    let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (server_ep, _cert) = lossy::lossy_server_endpoint(bind, 0.25, 0xA11CE).unwrap();
    let addr = server_ep.local_addr().unwrap();
    let clk = clock();

    let (tx, rx) = oneshot::channel::<Handle>();
    let srv_clk = clk.clone();
    let server_task = tokio::spawn(async move {
        let t = transport::accept(&server_ep).await.unwrap();
        let handle = spawn_driver(t, srv_clk);
        tx.send(handle).ok();
        std::future::pending::<()>().await;
    });

    let client_ep = lossy::lossy_insecure_client_endpoint(bind, 0.25, 0xB0B).unwrap();
    let t = transport::connect(&client_ep, addr, "localhost")
        .await
        .unwrap();
    let client = spawn_driver(t, clk);
    let mut server = rx.await.unwrap();

    client.set_local(BytesState::new(b"reliable over lossy QUIC".to_vec()));
    tokio::time::timeout(
        Duration::from_secs(30),
        await_state(&mut server, b"reliable over lossy QUIC"),
    )
    .await
    .expect("converged despite 25% datagram loss");

    server_task.abort();
}

#[tokio::test]
async fn quic_survives_client_migration() {
    // The headline mobile-shell feature: the client changes its local UDP
    // address mid-session (Wi-Fi → cellular, NAT rebind, resume) and the
    // connection — and SSP sync — carries on.
    let (server_ep, addr, _cert) = transport::loopback_server().unwrap();
    let clk = clock();

    let (tx, rx) = oneshot::channel::<(Handle, QuicTransport)>();
    let srv_clk = clk.clone();
    let server_task = tokio::spawn(async move {
        let t = transport::accept(&server_ep).await.unwrap();
        let probe = t.clone();
        let handle = spawn_driver(t, srv_clk);
        tx.send((handle, probe)).ok();
        std::future::pending::<()>().await;
    });

    let client_ep = transport::loopback_client().unwrap();
    let t = transport::connect(&client_ep, addr, "localhost")
        .await
        .unwrap();
    let client = spawn_driver(t, clk);
    let (mut server, server_probe) = rx.await.unwrap();

    // Establish sync on the original path.
    client.set_local(BytesState::new(b"before-roam".to_vec()));
    tokio::time::timeout(
        Duration::from_secs(10),
        await_state(&mut server, b"before-roam"),
    )
    .await
    .expect("initial sync");
    let addr_before = server_probe.remote_address();

    // Roam: rebind the client endpoint to a brand-new local UDP port.
    client_ep
        .rebind(std::net::UdpSocket::bind("127.0.0.1:0").unwrap())
        .expect("rebind to new local address");

    // New data after migration must still arrive.
    client.set_local(BytesState::new(b"after-roam".to_vec()));
    tokio::time::timeout(
        Duration::from_secs(10),
        await_state(&mut server, b"after-roam"),
    )
    .await
    .expect("sync continues after migration");

    let addr_after = server_probe.remote_address();
    assert_ne!(
        addr_before, addr_after,
        "server should observe the client's new address after migration"
    );

    server_task.abort();
}
