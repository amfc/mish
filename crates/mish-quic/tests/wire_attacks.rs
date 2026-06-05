//! Adversarial wire tests over a *real* QUIC connection (review §A.3): the
//! protocol must withstand on-path tampering/duplication and off-path injection.
//!
//! - **Tamper:** a bit-flipped datagram is rejected by QUIC's AEAD (never reaches
//!   the app), so it acts as loss — the session still converges via SSP healing.
//! - **Duplicate:** a duplicated datagram is dropped by QUIC's packet-number
//!   replay window; combined with SSP's idempotent, sequence-numbered diffs there
//!   is no double-apply — convergence is still exact.
//! - **Off-path inject:** UDP from a non-participant (no valid connection /
//!   failing AEAD) must not disrupt or hijack the established session.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use mish_ssp::clock::{Clock, SystemClock};
use mish_ssp::core::SspConfig;
use mish_ssp::session::{Driver, Session, SessionHandle};
use mish_ssp::states::BytesState;
use tokio::sync::oneshot;

use mish_quic::lossy::{self, Faults};
use mish_quic::transport::{self, QuicTransport};

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

/// Connect, run drivers both ways, and return the two handles once linked.
async fn link(
    server_ep: quinn::Endpoint,
    addr: SocketAddr,
    client_ep: quinn::Endpoint,
) -> (Handle, Handle, tokio::task::JoinHandle<()>) {
    let clk = clock();
    let (tx, rx) = oneshot::channel::<Handle>();
    let srv_clk = clk.clone();
    let task = tokio::spawn(async move {
        if let Ok(t) = transport::accept(&server_ep).await {
            let h = spawn_driver(t, srv_clk);
            let _ = tx.send(h);
        }
        std::future::pending::<()>().await;
    });
    let t = transport::connect(&client_ep, addr, "localhost")
        .await
        .expect("client connects");
    let client = spawn_driver(t, clk);
    let server = rx.await.expect("server handle");
    (client, server, task)
}

/// A bit-flipped datagram is AEAD-rejected; the session still converges.
#[tokio::test]
async fn tampered_datagrams_are_rejected_and_session_heals() {
    let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (server_ep, addr, _cert) = {
        let (ep, cert) = lossy::faulty_server_endpoint(
            bind,
            Faults {
                corrupt: 0.3,
                ..Default::default()
            },
            0xC0FFEE,
        )
        .unwrap();
        let a = ep.local_addr().unwrap();
        (ep, a, cert)
    };
    let client_ep = transport::loopback_client().unwrap();
    let (mut client, mut server, task) = link(server_ep, addr, client_ep).await;

    client.set_local(BytesState::new(b"client survives tampering".to_vec()));
    server.set_local(BytesState::new(b"server survives tampering".to_vec()));
    tokio::time::timeout(Duration::from_secs(20), async {
        await_state(&mut server, b"client survives tampering").await;
        await_state(&mut client, b"server survives tampering").await;
    })
    .await
    .expect("converges despite ~30% AEAD-rejected (corrupted) datagrams");
    task.abort();
}

/// Duplicated datagrams don't cause a double-apply; convergence stays exact.
#[tokio::test]
async fn duplicated_datagrams_do_not_corrupt_state() {
    let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (server_ep, addr, _cert) = lossy::faulty_server_endpoint(
        bind,
        Faults {
            dup: 0.5,
            ..Default::default()
        },
        0xD00D,
    )
    .map(|(ep, cert)| {
        let a = ep.local_addr().unwrap();
        (ep, a, cert)
    })
    .unwrap();
    let client_ep = transport::loopback_client().unwrap();
    let (mut client, server, task) = link(server_ep, addr, client_ep).await;

    // Push a sequence of states; duplicates must not desync the final value.
    for i in 0..6u32 {
        server.set_local(BytesState::new(format!("v{i}").into_bytes()));
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    server.set_local(BytesState::new(b"final".to_vec()));
    tokio::time::timeout(Duration::from_secs(15), await_state(&mut client, b"final"))
        .await
        .expect("converges to the exact final state despite duplication");
    task.abort();
}

/// Off-path UDP junk from a non-participant must not disrupt or hijack the
/// established session.
#[tokio::test]
async fn off_path_injection_does_not_disrupt() {
    let (server_ep, addr, _cert) = transport::loopback_server().unwrap();
    let client_ep = transport::loopback_client().unwrap();
    let (mut client, server, task) = link(server_ep, addr, client_ep).await;

    // Establish the session.
    server.set_local(BytesState::new(b"established".to_vec()));
    tokio::time::timeout(
        Duration::from_secs(10),
        await_state(&mut client, b"established"),
    )
    .await
    .expect("initial convergence");

    // An off-path attacker fires garbage UDP at the server's port.
    let attacker = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    for i in 0..100u8 {
        let junk = [i; 64];
        let _ = attacker.send_to(&junk, addr);
    }

    // The session is unharmed: a new state still propagates end-to-end.
    server.set_local(BytesState::new(b"after the junk flood".to_vec()));
    tokio::time::timeout(
        Duration::from_secs(10),
        await_state(&mut client, b"after the junk flood"),
    )
    .await
    .expect("off-path junk must neither disrupt nor hijack the session");
    task.abort();
}

/// An MTU black hole (the path silently drops datagrams larger than ~1200 bytes)
/// must not wedge the session: QUIC's DPLPMTUD keeps the packet size at the base
/// MTU and a large screen state still transfers (fragmented) and converges.
#[tokio::test]
async fn mtu_black_hole_still_converges() {
    let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (server_ep, addr, _cert) = lossy::faulty_server_endpoint(
        bind,
        Faults {
            // Drop anything above the QUIC Initial floor — DPLPMTUD probes for a
            // bigger MTU get black-holed, so the path stays at the base size.
            max_pass: Some(1252),
            ..Default::default()
        },
        0xB1A4,
    )
    .map(|(ep, cert)| {
        let a = ep.local_addr().unwrap();
        (ep, a, cert)
    })
    .unwrap();
    let client_ep = transport::loopback_client().unwrap();
    let (mut client, server, task) = link(server_ep, addr, client_ep).await;

    // A large state forces fragmentation across many base-MTU datagrams.
    let big = vec![b'Z'; 20 * 1024];
    server.set_local(BytesState::new(big.clone()));
    tokio::time::timeout(Duration::from_secs(20), await_state(&mut client, &big))
        .await
        .expect("large state must transfer through an MTU black hole");
    task.abort();
}

/// A pre-handshake junk flood (garbage UDP arriving before any legitimate
/// connection) must not exhaust or crash the server: a real client can still
/// connect and converge afterwards. (QUIC's 3x anti-amplification limit — the
/// server never reflects more than 3x an unvalidated peer's bytes — is enforced
/// by quinn and isn't re-tested here; that would require spoofed-Initial packet
/// crafting against the QUIC stack itself.)
#[tokio::test]
async fn server_survives_pre_handshake_junk_flood() {
    let (server_ep, addr, _cert) = transport::loopback_server().unwrap();
    let clk = clock();
    let (tx, rx) = oneshot::channel::<Handle>();
    let srv_clk = clk.clone();
    let task = tokio::spawn(async move {
        if let Ok(t) = transport::accept(&server_ep).await {
            let _ = tx.send(spawn_driver(t, srv_clk));
        }
        std::future::pending::<()>().await;
    });

    // Flood the server port with garbage *before* any handshake.
    let attacker = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    for i in 0..500u32 {
        let junk = [(i & 0xff) as u8; 200];
        let _ = attacker.send_to(&junk, addr);
    }

    // A legitimate client still connects and converges.
    let client_ep = transport::loopback_client().unwrap();
    let t = transport::connect(&client_ep, addr, "localhost")
        .await
        .expect("server still accepts a real client after the junk flood");
    let mut client = spawn_driver(t, clk);
    let server = rx.await.expect("server handle");
    server.set_local(BytesState::new(b"alive after flood".to_vec()));
    tokio::time::timeout(
        Duration::from_secs(10),
        await_state(&mut client, b"alive after flood"),
    )
    .await
    .expect("server must remain usable after a pre-handshake junk flood");
    task.abort();
}
