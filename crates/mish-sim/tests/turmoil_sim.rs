//! Deterministic network-simulation tests with `turmoil`.
//!
//! Each test stands up two simulated hosts — an echo "server" and a "client" —
//! and runs the **real** async SSP [`Driver`] over [`TurmoilUdpTransport`]
//! (simulated UDP). turmoil controls the clock and injects latency, packet
//! loss, and partitions, reproducibly from a seed. The client sends `ping`,
//! the server echoes `ping-ack`; observing `ping-ack` proves the round trip
//! survived whatever the network did to it.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use mish_ssp::clock::{Clock, TokioClock};
use mish_ssp::core::SspConfig;
use mish_ssp::session::{Driver, Session};
use mish_ssp::states::BytesState;
use mish_sim::TurmoilUdpTransport;

const PORT: u16 = 9000;

fn sim_config() -> SspConfig {
    // Snappy timers so convergence happens within simulated seconds.
    SspConfig {
        rto: 300,
        ack_interval: 500,
        ack_delay: 20,
        send_interval_min: 20,
        ..Default::default()
    }
}

fn local_any() -> SocketAddr {
    SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0)
}

/// Build a driver over a transport and return its session handle.
fn session(
    transport: TurmoilUdpTransport,
) -> mish_ssp::session::SessionHandle<BytesState, BytesState> {
    let clock: Arc<dyn Clock> = Arc::new(TokioClock::new());
    let (driver, handle) =
        Driver::<_, BytesState, BytesState>::with(Arc::new(transport), clock, sim_config());
    driver.spawn();
    handle
}

/// Run an echo endpoint forever: whatever it receives, it sends back with an
/// `-ack` suffix.
async fn echo_server() -> turmoil::Result {
    let transport = TurmoilUdpTransport::bind_server(SocketAddr::new(
        Ipv4Addr::UNSPECIFIED.into(),
        PORT,
    ))
    .await
    .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
    let handle = session(transport);

    let mut remote = handle.subscribe_remote();
    loop {
        if remote.changed().await.is_err() {
            return Ok(());
        }
        let v = remote.borrow_and_update().0.clone();
        if !v.is_empty() && !v.ends_with(b"-ack") {
            let mut out = v;
            out.extend_from_slice(b"-ack");
            handle.set_local(BytesState(out));
        }
    }
}

/// Connect, send `payload`, and wait up to `budget` for the echoed `*-ack`.
async fn ping_expect_ack(payload: Vec<u8>, budget: Duration) -> turmoil::Result {
    let server = SocketAddr::new(turmoil::lookup("server"), PORT);
    let transport = TurmoilUdpTransport::connect(local_any(), server)
        .await
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
    let handle = session(transport);

    let mut expected = payload.clone();
    expected.extend_from_slice(b"-ack");
    handle.set_local(BytesState(payload));

    let mut remote = handle.subscribe_remote();
    let ok = tokio::time::timeout(budget, async {
        loop {
            if remote.changed().await.is_err() {
                return false;
            }
            if remote.borrow_and_update().0 == expected {
                return true;
            }
        }
    })
    .await
    .unwrap_or(false);

    if ok {
        Ok(())
    } else {
        Err("client did not observe the echoed ack within budget".into())
    }
}

#[test]
fn converges_with_latency() {
    let mut sim = turmoil::Builder::new()
        .min_message_latency(Duration::from_millis(10))
        .max_message_latency(Duration::from_millis(100))
        .simulation_duration(Duration::from_secs(60))
        .build();

    sim.host("server", echo_server);
    sim.client(
        "client",
        ping_expect_ack(b"ping".to_vec(), Duration::from_secs(30)),
    );

    sim.run().unwrap();
}

#[test]
fn converges_under_packet_loss() {
    let mut sim = turmoil::Builder::new()
        .min_message_latency(Duration::from_millis(10))
        .max_message_latency(Duration::from_millis(80))
        .fail_rate(0.30) // 30% of datagrams dropped, both directions
        .simulation_duration(Duration::from_secs(120))
        .build();

    sim.host("server", echo_server);
    sim.client(
        "client",
        ping_expect_ack(b"ping".to_vec(), Duration::from_secs(90)),
    );

    sim.run().unwrap();
}

#[test]
fn large_payload_fragments_and_converges_under_loss() {
    // ~10 KB payload → many MTU-sized fragments; with loss, a dropped fragment
    // loses the whole instruction and SSP re-diffs. Exercises fragmentation +
    // reassembly + recovery under simulation.
    let mut sim = turmoil::Builder::new()
        .min_message_latency(Duration::from_millis(5))
        .max_message_latency(Duration::from_millis(40))
        .fail_rate(0.05)
        .simulation_duration(Duration::from_secs(120))
        .build();

    let payload: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
    sim.host("server", echo_server);
    sim.client(
        "client",
        ping_expect_ack(payload, Duration::from_secs(90)),
    );

    sim.run().unwrap();
}

#[test]
fn survives_network_partition() {
    // Partition the client from the server for a stretch of simulated time,
    // then heal it. SSP must converge after the partition repairs.
    let mut sim = turmoil::Builder::new()
        .min_message_latency(Duration::from_millis(10))
        .max_message_latency(Duration::from_millis(80))
        .simulation_duration(Duration::from_secs(120))
        .build();

    sim.host("server", echo_server);
    sim.client(
        "client",
        ping_expect_ack(b"ping".to_vec(), Duration::from_secs(90)),
    );

    // Cut the link immediately and keep it down for ~15s of simulated time.
    sim.partition("client", "server");
    while sim.elapsed() < Duration::from_secs(15) {
        sim.step().unwrap();
    }
    // Heal the network; the client should now converge before its budget.
    sim.repair("client", "server");

    sim.run().unwrap();
}
