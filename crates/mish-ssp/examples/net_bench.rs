//! Protocol / latency benchmark for the SSP core, run over the deterministic
//! virtual-time simulator (`mish_ssp::sim`). It answers the questions the diff
//! benchmark can't: how long does a state change take to reach the peer, how
//! much does loss cost, and how many datagrams does a change take?
//!
//! It's *virtual time* — no wall clock — so the numbers are the protocol's own
//! latency (send-cadence gating, retransmit timing, the prophylactic-resend
//! recovery), independent of CPU speed and perfectly reproducible by seed.
//!
//! ```sh
//! cargo run -p mish-ssp --release --example net_bench
//! ```

use mish_ssp::core::SspConfig;
use mish_ssp::sim::{NetworkSim, SimConfig};
use mish_ssp::states::BytesState;

/// Measure single-change convergence latency (ms of virtual time from a state
/// change at A until B has it) for `n_keys` successive one-byte changes, plus
/// the average datagrams sent per change. Returns all per-change latencies.
fn run_trial(
    one_way: u64,
    loss: f64,
    prospective: bool,
    seed: u64,
    n_keys: usize,
) -> (Vec<u64>, f64) {
    let ssp = SspConfig {
        prospective_resend: prospective,
        ..SspConfig::default()
    };
    let cfg = SimConfig {
        loss,
        loss_return: Some(loss),
        min_delay: one_way,
        max_delay: one_way,
        seed,
        ssp,
        ..SimConfig::default()
    };
    let mut sim = NetworkSim::<BytesState, BytesState>::new(cfg);

    // Settle the connection (initial acks, RTT estimate) before measuring.
    sim.run_until(|_| false, 2000);

    let mut state: Vec<u8> = b"start".to_vec();
    {
        let target = state.clone();
        sim.set_a_local(BytesState::new(target.clone()));
        let budget = sim.now() + 60_000;
        sim.run_until(|s| s.b_view_of_a().as_slice() == target.as_slice(), budget);
    }

    let mut lats = Vec::with_capacity(n_keys);
    let mut sent_total = 0u64;
    for k in 0..n_keys {
        state.push(b'a' + (k % 26) as u8);
        let target = state.clone();
        sim.set_a_local(BytesState::new(target.clone()));
        let start = sim.now();
        let sent_before = sim.sent;
        let budget = start + 60_000;
        let ok = sim.run_until(|s| s.b_view_of_a().as_slice() == target.as_slice(), budget);
        if ok {
            lats.push(sim.now() - start);
            sent_total += sim.sent - sent_before;
        }
    }
    let avg_sent = if lats.is_empty() {
        0.0
    } else {
        sent_total as f64 / lats.len() as f64
    };
    (lats, avg_sent)
}

/// Drive a fast continuous output stream (a change every 10 ms) over a lossy
/// link and measure the *mean lag* — how many changes behind A's current state
/// B runs, sampled across the stream. This is what prophylactic resend improves:
/// with a dropped datagram, a diff anchored on un-delivered state can't be
/// applied, so B falls behind until we re-anchor on the acked state.
fn stream_mean_lag(one_way: u64, loss: f64, prospective: bool, seed: u64) -> f64 {
    let ssp = SspConfig {
        prospective_resend: prospective,
        ..SspConfig::default()
    };
    let cfg = SimConfig {
        loss,
        loss_return: Some(loss),
        min_delay: one_way,
        max_delay: one_way,
        seed,
        ssp,
        ..SimConfig::default()
    };
    let mut sim = NetworkSim::<BytesState, BytesState>::new(cfg);
    sim.run_until(|_| false, 2000);

    let mut state: Vec<u8> = b"start".to_vec();
    let mut lag_sum = 0u64;
    let mut samples = 0u64;
    for i in 0..120 {
        let t = sim.now() + 10;
        sim.run_until(|s| s.now() >= t, t);
        state.push(b'a' + (i % 26) as u8);
        sim.set_a_local(BytesState::new(state.clone()));
        // Lag = how many bytes (changes) B's view trails A's current state.
        let b_len = sim.b_view_of_a().as_slice().len();
        lag_sum += state.len().saturating_sub(b_len) as u64;
        samples += 1;
    }
    lag_sum as f64 / samples as f64
}

/// Mean lag across seeds.
fn stream_lag(one_way: u64, loss: f64, prospective: bool) -> f64 {
    let n = 25u64;
    (0..n)
        .map(|s| stream_mean_lag(one_way, loss, prospective, s * 0x9E3779B1 + 1))
        .sum::<f64>()
        / n as f64
}

/// Aggregate latencies across seeds → (median, p90) ms.
fn percentiles(one_way: u64, loss: f64, prospective: bool) -> (u64, u64, f64) {
    let mut all = Vec::new();
    let mut sent_acc = 0.0;
    let seeds = 25u64;
    for seed in 0..seeds {
        let (lats, avg_sent) = run_trial(one_way, loss, prospective, seed * 0x9E3779B1 + 1, 30);
        all.extend(lats);
        sent_acc += avg_sent;
    }
    all.sort_unstable();
    let median = all.get(all.len() / 2).copied().unwrap_or(0);
    let p90 = all.get(all.len() * 9 / 10).copied().unwrap_or(0);
    (median, p90, sent_acc / seeds as f64)
}

fn main() {
    println!("mish protocol/latency benchmark (virtual time)\n");

    // 1. Single-keystroke convergence latency vs RTT, on a clean link. Shows the
    //    protocol adds only the send-cadence gating over the raw one-way delay.
    println!("Single-change convergence latency, no loss (median / p90):");
    for &rtt in &[10u64, 50, 150, 300] {
        let one_way = rtt / 2;
        let (med, p90, _) = percentiles(one_way, 0.0, true);
        println!("  RTT {rtt:>4}ms (one-way {one_way:>3}):  {med:>4} / {p90:>4} ms");
    }

    // 2. Single-change latency under loss (RTT 150): the median stays at the
    //    no-loss floor (the change usually gets through), but the p90 tail grows
    //    as some changes wait for a retransmit.
    println!("\nSingle-change latency under loss, RTT 150ms (median / p90):");
    for &loss in &[0.0, 0.10, 0.30, 0.50] {
        let (med, p90, _) = percentiles(75, loss, true);
        println!(
            "  loss {:>3}:  {med:>4} / {p90:>4} ms",
            format!("{:.0}%", loss * 100.0)
        );
    }

    // 3. The prophylactic-resend win: under fast continuous output with loss, how
    //    far behind (in changes) does B run? Lower is better. Re-anchoring on the
    //    acked state keeps B closer to current when datagrams drop.
    println!("\nMean lag during fast streaming, RTT 150ms — resend ON vs OFF (lower better):");
    println!("       loss      ON       OFF");
    for &loss in &[0.10, 0.30, 0.50] {
        let on = stream_lag(75, loss, true);
        let off = stream_lag(75, loss, false);
        println!(
            "  {:>9}   {on:>5.1}   {off:>5.1}  changes behind",
            format!("{:.0}%", loss * 100.0)
        );
    }

    // 3. Datagrams sent per change, vs loss (retransmits inflate it).
    println!("\nDatagrams sent per change (RTT 150ms):");
    for &loss in &[0.0, 0.10, 0.30, 0.50] {
        let (_, _, sent) = percentiles(75, loss, true);
        println!("  loss {:>3}:  {sent:>4.1}", format!("{:.0}%", loss * 100.0));
    }
}
