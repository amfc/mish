//! Deterministic simulation of the SSP core under `madsim` — a second engine
//! alongside `turmoil`. madsim controls the clock, network latency, packet loss,
//! and RNG, so a run is fully reproducible from `MADSIM_TEST_SEED`.
//!
//! Compiles only under `--cfg madsim`; run with:
//! `RUSTFLAGS="--cfg madsim" cargo test -p mish-madsim`
//!
//! The SSP core is sans-IO, so we drive `tick`/`recv` by hand over madsim's
//! simulated UDP — no tokio runtime involved.
#![cfg(madsim)]

use std::net::SocketAddr;
use std::time::Duration;

use madsim::net::UdpSocket;
use madsim::runtime::Handle;
use madsim::time::{timeout, Instant};

use mish_ssp::core::{SspConfig, SspCore};
use mish_ssp::instruction::Instruction;
use mish_ssp::states::BytesState;

const PORT: u16 = 9000;

fn cfg() -> SspConfig {
    SspConfig {
        rto: 300,
        ack_interval: 500,
        ack_delay: 20,
        send_interval_min: 20,
        ..Default::default()
    }
}

/// Echo endpoint: whatever it receives, it sends back with an `-ack` suffix.
async fn echo_server(addr: SocketAddr) {
    let sock = UdpSocket::bind(addr).await.unwrap();
    let mut core = SspCore::<BytesState, BytesState>::with_config(0, cfg());
    let start = Instant::now();
    let mut peer: Option<SocketAddr> = None;
    let mut buf = vec![0u8; 65536];
    loop {
        let now = start.elapsed().as_millis() as u64;
        for inst in core.tick(now) {
            if let Some(p) = peer {
                let _ = sock.send_to(p, &inst.encode()).await;
            }
        }
        let r = core.remote_state().0.clone();
        if !r.is_empty() && !r.ends_with(b"-ack") {
            let mut v = r;
            v.extend_from_slice(b"-ack");
            core.set_current_state(BytesState(v));
        }
        let wait = core.wait_time(now).unwrap_or(3_600_000).max(1);
        if let Ok(Ok((n, from))) =
            timeout(Duration::from_millis(wait), sock.recv_from(&mut buf)).await
        {
            peer = Some(from);
            let now2 = start.elapsed().as_millis() as u64;
            if let Some(inst) = Instruction::decode(&buf[..n]) {
                core.recv(now2, &inst);
            }
        }
    }
}

/// Send `payload`, wait for the echoed `*-ack`.
async fn ping_client(server: SocketAddr, payload: Vec<u8>) -> bool {
    let sock = UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0))
        .await
        .unwrap();
    let mut core = SspCore::<BytesState, BytesState>::with_config(0, cfg());
    core.set_current_state(BytesState(payload.clone()));
    let mut expected = payload;
    expected.extend_from_slice(b"-ack");

    let start = Instant::now();
    let mut buf = vec![0u8; 65536];
    while start.elapsed() < Duration::from_secs(90) {
        let now = start.elapsed().as_millis() as u64;
        for inst in core.tick(now) {
            let _ = sock.send_to(server, &inst.encode()).await;
        }
        if core.remote_state().0 == expected {
            return true;
        }
        let wait = core.wait_time(now).unwrap_or(3_600_000).max(1);
        if let Ok(Ok((n, _))) =
            timeout(Duration::from_millis(wait), sock.recv_from(&mut buf)).await
        {
            let now2 = start.elapsed().as_millis() as u64;
            if let Some(inst) = Instruction::decode(&buf[..n]) {
                core.recv(now2, &inst);
            }
        }
    }
    core.remote_state().0 == expected
}

async fn run_scenario(loss: f64) -> bool {
    let handle = Handle::current();
    madsim::net::NetSim::current().update_config(|c| {
        c.packet_loss_rate = loss;
        c.send_latency = Duration::from_millis(5)..Duration::from_millis(60);
    });

    let server_ip = "10.0.0.1".parse().unwrap();
    let server = handle.create_node().ip(server_ip).build();
    let client = handle.create_node().ip("10.0.0.2".parse().unwrap()).build();
    let saddr = SocketAddr::new(server_ip, PORT);

    server.spawn(async move { echo_server(saddr).await });
    client
        .spawn(async move { ping_client(saddr, b"ping".to_vec()).await })
        .await
        .unwrap()
}

#[madsim::test]
async fn converges_with_latency() {
    assert!(run_scenario(0.0).await, "should converge with latency");
}

#[madsim::test]
async fn converges_under_packet_loss() {
    assert!(run_scenario(0.3).await, "should converge under 30% loss");
}
