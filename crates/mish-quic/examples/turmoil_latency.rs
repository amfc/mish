//! Deterministic keyboard-latency measurement with the **real QUIC stack** in the
//! loop, over turmoil's simulated network.
//!
//! This is the quinn-in-the-loop counterpart to `mish-ssp`'s sans-IO `tail_probe`:
//! same keystroke→echo round-trip measurement, but the bytes traverse an actual
//! [`QuicTransport`](mish_quic::QuicTransport) running on turmoil's controllable
//! clock + fault model. So QUIC's own contribution (framing, ack scheduling, the
//! real RTT estimator, congestion control) is included — and the result is
//! reproducible and instant, instead of a slow, noisy wall-clock bench run.
//!
//! Run: `cargo run -p mish-quic --features turmoil --example turmoil_latency -- [COND]`
//!   COND ∈ {LAN,WAN,LOSSY,BURSTY,BRUTAL} (default BRUTAL). KEYS env sets the
//!   keystroke count (default 300). The SSP timing knobs (`MISH_SSP_*`) apply.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mish_quic::turmoil_sim::{turmoil_insecure_client_endpoint, turmoil_server_endpoint};
use mish_ssp::clock::{Clock, TokioClock};
use mish_ssp::core::SspConfig;
use mish_ssp::session::{Driver, Session, SessionHandle};
use mish_ssp::states::BytesState;

const PORT: u16 = 9000;

/// One simulated network condition (turmoil applies latency/loss/reorder).
#[derive(Clone, Copy)]
struct Cond {
    /// One-way latency floor / ceiling (ms). A gap (min < max) produces jitter
    /// *and* reordering, exactly like the relay's jitter knob.
    lat_min: u64,
    lat_max: u64,
    /// Per-datagram drop probability (turmoil's `fail_rate`, both directions).
    loss: f64,
}

fn cond(name: &str) -> Cond {
    match name {
        "LAN" => Cond {
            lat_min: 1,
            lat_max: 2,
            loss: 0.0,
        },
        "WAN" => Cond {
            lat_min: 38,
            lat_max: 45,
            loss: 0.05,
        },
        "LOSSY" => Cond {
            lat_min: 55,
            lat_max: 70,
            loss: 0.15,
        },
        "BURSTY" => Cond {
            lat_min: 35,
            lat_max: 50,
            loss: 0.14,
        },
        // BRUTAL: high RTT + heavy loss + wide jitter (⇒ reordering).
        _ => Cond {
            lat_min: 60,
            lat_max: 150,
            loss: 0.20,
        },
    }
}

fn ssp_config() -> SspConfig {
    SspConfig::default().with_env_overrides()
}

fn local_any() -> SocketAddr {
    SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0)
}

/// Wrap a transport in an SSP driver, returning its handle.
fn session<T: mish_ssp::Transport>(transport: T) -> SessionHandle<BytesState, BytesState> {
    let clock: Arc<dyn Clock> = Arc::new(TokioClock::new());
    let (driver, handle) =
        Driver::<_, BytesState, BytesState>::with(Arc::new(transport), clock, ssp_config());
    driver.spawn();
    handle
}

/// Server: accept one QUIC connection and echo every byte it receives back into
/// its own state (the "screen"), like `cat` over a PTY.
async fn echo_server() -> turmoil::Result {
    let (endpoint, _cert) =
        turmoil_server_endpoint(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), PORT)).await?;
    let transport = mish_quic::accept(&endpoint).await?;
    let handle = session(transport);

    let mut remote = handle.subscribe_remote();
    loop {
        if remote.changed().await.is_err() {
            return Ok(());
        }
        let v = remote.borrow_and_update().0.clone();
        // Echo: server's local state mirrors everything received from the client.
        handle.set_local(BytesState(v));
    }
}

fn pct(mut v: Vec<f64>, p: f64) -> f64 {
    if v.is_empty() {
        return f64::NAN;
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((v.len() as f64 * p) as usize).min(v.len() - 1)]
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let name = args.get(1).cloned().unwrap_or_else(|| "BRUTAL".into());
    let c = cond(&name);
    let keys: usize = std::env::var("KEYS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(300);

    // Latencies collected by the client host, read back after the sim ends.
    let samples: Arc<Mutex<Vec<f64>>> = Arc::new(Mutex::new(Vec::new()));

    let mut sim = turmoil::Builder::new()
        .min_message_latency(Duration::from_millis(c.lat_min))
        .max_message_latency(Duration::from_millis(c.lat_max))
        .fail_rate(c.loss)
        .simulation_duration(Duration::from_secs(600))
        .build();

    sim.host("server", echo_server);

    let out = samples.clone();
    sim.client("client", async move {
        let endpoint = turmoil_insecure_client_endpoint(local_any()).await?;
        let server = SocketAddr::new(turmoil::lookup("server"), PORT);
        let transport = mish_quic::connect(&endpoint, server, "localhost").await?;
        let handle = session(transport);
        let mut remote = handle.subscribe_remote();

        // Let the handshake + initial sync settle.
        tokio::time::sleep(Duration::from_millis(500)).await;

        let mut typed: Vec<u8> = Vec::new();
        for k in 0..keys {
            typed.push(b'a' + (k % 26) as u8);
            let target = typed.len();
            let t0 = tokio::time::Instant::now();
            handle.set_local(BytesState(typed.clone()));

            // Wait until the echoed glyph returns (our view of the server's state
            // reaches `target`), capped at a 3 s patience like the live harness.
            let got = tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    if remote.borrow().0.len() >= target {
                        return true;
                    }
                    if remote.changed().await.is_err() {
                        return false;
                    }
                }
            })
            .await
            .unwrap_or(false);

            if got {
                out.lock()
                    .unwrap()
                    .push(t0.elapsed().as_secs_f64() * 1000.0);
            }
            tokio::time::sleep(Duration::from_millis(40)).await; // inter-keystroke gap
        }
        Ok(())
    });

    sim.run().expect("simulation failed");

    let all = Arc::try_unwrap(samples).unwrap().into_inner().unwrap();
    let n = all.len();
    let mean = all.iter().sum::<f64>() / n as f64;
    let cfg = ssp_config();
    println!(
        "TURMOIL+QUIC {name}  lat={}-{}ms loss={:.0}%  rto_factor={} keys={keys}",
        c.lat_min,
        c.lat_max,
        c.loss * 100.0,
        cfg.rto_srtt_factor,
    );
    println!(
        "  n={n}/{keys} echoed   median={:.1}  p90={:.1}  mean={mean:.1} ms",
        pct(all.clone(), 0.5),
        pct(all, 0.9),
    );
}
