//! Deterministic keystroke→echo round-trip latency probe — **no quinn**.
//!
//! Drives two bare [`SspCore`]s through a fault-injecting virtual-time link whose
//! loss/delay/reorder model is copied byte-for-byte from the bench-harness relay,
//! so the impairment is *identical* to the live BRUTAL/LOSSY/WAN conditions —
//! only the transport differs (this is the SSP protocol alone, no QUIC).
//!
//! Goal: decompose the BRUTAL keyboard tail. mish-real (= this core + quinn)
//! shows p90 ~640 ms vs mosh-real ~320 ms. Both run *the same protocol*. So:
//!   - if this core-only sim already shows a ~640 ms tail → the tail is the
//!     protocol's resend cadence, and quinn adds ~nothing;
//!   - if it shows a ~320 ms (mosh-like) tail → the extra in mish-real is quinn.
//!
//! And the `--send-max` knob clamps the resend cadence, so we can see *in the
//! protocol* whether a tighter cadence shrinks the tail (the Exp-B hypothesis).
//!
//! Run: `cargo run -p mish-ssp --release --example tail_probe -- [COND] [send_max_ms]`
//!   COND ∈ {BRUTAL,LOSSY,WAN,BURSTY,REORDER}; send_max_ms overrides
//!   `send_interval_max` (default 250). Seeds/keystrokes via SEEDS/KEYS env.

use mish_ssp::clock::Millis;
use mish_ssp::core::{ResendMode, SspConfig, SspCore};
use mish_ssp::instruction::Instruction;
use mish_ssp::states::BytesState;

// ----- loss/delay model, copied from bench-harness/src/main.rs -----

#[derive(Clone, Copy)]
enum LossModel {
    Iid(f64),
    Gilbert {
        good_loss: f64,
        bad_loss: f64,
        p_enter_bad: f64,
        p_leave_bad: f64,
    },
}

#[derive(Clone, Copy)]
struct Faults {
    delay_ms: u64,
    jitter_ms: u64,
    loss: LossModel,
    reorder_prob: f64,
    reorder_extra_ms: u64,
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
    fn f64(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }
}

/// Per-direction Gilbert-Elliott chain state (identical to the relay's).
struct LossState {
    in_bad: bool,
}
impl LossState {
    fn new() -> Self {
        Self { in_bad: false }
    }
    fn drops(&mut self, model: &LossModel, r: &mut Rng) -> bool {
        match *model {
            LossModel::Iid(p) => r.f64() < p,
            LossModel::Gilbert {
                good_loss,
                bad_loss,
                p_enter_bad,
                p_leave_bad,
            } => {
                if self.in_bad {
                    if r.f64() < p_leave_bad {
                        self.in_bad = false;
                    }
                } else if r.f64() < p_enter_bad {
                    self.in_bad = true;
                }
                let loss = if self.in_bad { bad_loss } else { good_loss };
                r.f64() < loss
            }
        }
    }
}

fn condition(name: &str) -> Faults {
    match name {
        "WAN" => Faults {
            delay_ms: 40,
            jitter_ms: 5,
            loss: LossModel::Iid(0.05),
            reorder_prob: 0.0,
            reorder_extra_ms: 0,
        },
        "LOSSY" => Faults {
            delay_ms: 60,
            jitter_ms: 15,
            loss: LossModel::Iid(0.15),
            reorder_prob: 0.0,
            reorder_extra_ms: 0,
        },
        "BURSTY" => Faults {
            delay_ms: 40,
            jitter_ms: 10,
            loss: LossModel::Gilbert {
                good_loss: 0.005,
                bad_loss: 0.7,
                p_enter_bad: 0.0625,
                p_leave_bad: 0.25,
            },
            reorder_prob: 0.0,
            reorder_extra_ms: 0,
        },
        "REORDER" => Faults {
            delay_ms: 30,
            jitter_ms: 8,
            loss: LossModel::Iid(0.01),
            reorder_prob: 0.12,
            reorder_extra_ms: 60,
        },
        // BRUTAL minus the explicit reorder (same bursty loss + jitter): isolates
        // whether the +80 ms reordered packets are what inflate rttvar → RTO.
        "BRUTAL_NOREORDER" => Faults {
            delay_ms: 70,
            jitter_ms: 25,
            loss: LossModel::Gilbert {
                good_loss: 0.01,
                bad_loss: 0.6,
                p_enter_bad: 0.04,
                p_leave_bad: 0.2,
            },
            reorder_prob: 0.0,
            reorder_extra_ms: 0,
        },
        // BRUTAL (default): rtt~140, bursty + reorder.
        _ => Faults {
            delay_ms: 70,
            jitter_ms: 25,
            loss: LossModel::Gilbert {
                good_loss: 0.01,
                bad_loss: 0.6,
                p_enter_bad: 0.04,
                p_leave_bad: 0.2,
            },
            reorder_prob: 0.10,
            reorder_extra_ms: 80,
        },
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Dest {
    A, // client (types; receives the screen echo)
    B, // server (echoes received input into its screen)
}

struct InFlight {
    deliver: Millis,
    dest: Dest,
    inst: Instruction,
}

/// One end-to-end virtual-time session over the fault link. Returns completed
/// round-trip latencies (ms); keystrokes that don't echo within `patience` are
/// skipped, exactly as the live harness does.
struct SessionOut {
    samples: Vec<f64>,
    fwd_sends: u64, // datagrams the client put on the wire (incl. retransmits)
    final_srtt: f64,
}

fn session(faults: Faults, cfg: SspConfig, seed: u64, keys: usize, patience: Millis) -> SessionOut {
    let mut a: SspCore<BytesState, BytesState> = SspCore::with_config(0, cfg); // client
    let mut b: SspCore<BytesState, BytesState> = SspCore::with_config(0, cfg); // server
    let mut now: Millis = 0;
    let mut in_flight: Vec<InFlight> = Vec::new();

    // Per-direction RNG + Gilbert state, like the relay (forward A→B, return B→A).
    let mut fwd_rng = Rng(seed | 1);
    let mut ret_rng = Rng(seed.wrapping_mul(0x9E3779B97F4A7C15) | 1);
    let mut fwd_loss = LossState::new();
    let mut ret_loss = LossState::new();
    let mut delay_rng = Rng(seed.wrapping_mul(0xD1B54A32D192ED03) | 1);

    let mut typed: Vec<u8> = Vec::new();
    let mut samples = Vec::new();
    let mut fwd_sends: u64 = 0;

    let schedule = |now: Millis,
                    from: Dest,
                    instrs: Vec<Instruction>,
                    in_flight: &mut Vec<InFlight>,
                    loss: &mut LossState,
                    rng: &mut Rng,
                    delay_rng: &mut Rng|
     -> u64 {
        let dest = if from == Dest::A { Dest::B } else { Dest::A };
        let attempted = instrs.len() as u64;
        for inst in instrs {
            if loss.drops(&faults.loss, rng) {
                continue;
            }
            let jitter = if faults.jitter_ms > 0 {
                delay_rng.next() % (faults.jitter_ms + 1)
            } else {
                0
            };
            let reorder = if faults.reorder_prob > 0.0 && delay_rng.f64() < faults.reorder_prob {
                faults.reorder_extra_ms
            } else {
                0
            };
            let delay = faults.delay_ms + jitter + reorder;
            in_flight.push(InFlight {
                deliver: now + delay as Millis,
                dest,
                inst,
            });
        }
        attempted
    };

    for k in 0..keys {
        // Type one keystroke: append a byte to the client's UserStream.
        typed.push(b'a' + (k % 26) as u8);
        a.set_current_state(BytesState(typed.clone()));
        let typed_at = now;
        let target_len = typed.len();
        let deadline = now + patience;

        // Advance until the echoed glyph returns to the client (a's view of the
        // server screen reaches target_len), or patience runs out.
        loop {
            if a.remote_state().0.len() >= target_len {
                samples.push((now - typed_at) as f64);
                break;
            }
            if now > deadline {
                break; // skipped sample, matching the live harness
            }

            // Server echoes everything it has received from the client.
            let seen = b.remote_state().clone();
            b.set_current_state(seen);

            let aw = a.next_wakeup(now);
            let bw = b.next_wakeup(now);
            let dw = in_flight.iter().map(|f| f.deliver).min();
            let next = [aw, bw, dw].into_iter().flatten().min();
            let next = match next {
                Some(t) => t.max(now),
                None => break,
            };
            now = next;

            // Deliver everything due at or before now.
            let mut i = 0;
            while i < in_flight.len() {
                if in_flight[i].deliver <= now {
                    let f = in_flight.swap_remove(i);
                    match f.dest {
                        Dest::A => a.recv(now, &f.inst),
                        Dest::B => b.recv(now, &f.inst),
                    }
                } else {
                    i += 1;
                }
            }
            // Server echoes again so freshly-received input is in the screen
            // before it ticks.
            let seen = b.remote_state().clone();
            b.set_current_state(seen);

            let a_out = a.tick(now);
            fwd_sends += schedule(
                now,
                Dest::A,
                a_out,
                &mut in_flight,
                &mut fwd_loss,
                &mut fwd_rng,
                &mut delay_rng,
            );
            let b_out = b.tick(now);
            schedule(
                now,
                Dest::B,
                b_out,
                &mut in_flight,
                &mut ret_loss,
                &mut ret_rng,
                &mut delay_rng,
            );
        }
        now += 40; // inter-keystroke gap, like measure_keyboard
    }
    SessionOut {
        samples,
        fwd_sends,
        final_srtt: a.srtt_ms(),
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
    let cond = args.get(1).cloned().unwrap_or_else(|| "BRUTAL".into());
    let faults = condition(&cond);
    let mut cfg = SspConfig::default();
    if let Some(sm) = args.get(2).and_then(|s| s.parse::<Millis>().ok()) {
        cfg.send_interval_max = sm;
    }
    // Diagnostic knobs to bisect the tail within the protocol (no quinn).
    if let Some(v) = std::env::var("SEND_MIN").ok().and_then(|s| s.parse().ok()) {
        cfg.send_interval_min = v;
    }
    if let Some(v) = std::env::var("RTO").ok().and_then(|s| s.parse().ok()) {
        cfg.rto = v;
    }
    if let Some(v) = std::env::var("PROSPECTIVE")
        .ok()
        .and_then(|s| s.parse::<u8>().ok())
    {
        cfg.prospective_resend = v != 0;
    }
    // RESEND=rto|frame|frame_on_loss selects the retransmit cadence under loss.
    if let Ok(v) = std::env::var("RESEND") {
        cfg.resend_mode = match v.as_str() {
            "frame" => ResendMode::FrameRate,
            "frame_on_loss" => ResendMode::FrameRateOnLoss,
            _ => ResendMode::Rto,
        };
    }
    let seeds: u64 = std::env::var("SEEDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(15);
    let keys: usize = std::env::var("KEYS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(200);

    let mut all = Vec::new();
    let mut seed_medians = Vec::new();
    let mut completed = 0usize;
    let mut attempted = 0usize;
    let mut fwd_sends: u64 = 0;
    let mut srtt_sum = 0.0;
    for s in 0..seeds {
        let seed = 0x9E3779B1u64.wrapping_mul(s + 1);
        let out = session(faults, cfg, seed, keys, 3000);
        attempted += keys;
        completed += out.samples.len();
        fwd_sends += out.fwd_sends;
        srtt_sum += out.final_srtt;
        if !out.samples.is_empty() {
            seed_medians.push(pct(out.samples.clone(), 0.5));
        }
        all.extend(out.samples);
    }

    let n = all.len();
    let mean = all.iter().sum::<f64>() / n as f64;
    let var = all.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n as f64;
    let sd = var.sqrt();
    let sm_mean = seed_medians.iter().sum::<f64>() / seed_medians.len() as f64;
    let sm_var = seed_medians
        .iter()
        .map(|x| (x - sm_mean).powi(2))
        .sum::<f64>()
        / seed_medians.len() as f64;

    println!(
        "SIM (no quinn) {cond}  send=[{},{}]ms rto={} prospective={} resend={:?}  seeds={seeds} keys={keys}",
        cfg.send_interval_min, cfg.send_interval_max, cfg.rto, cfg.prospective_resend, cfg.resend_mode
    );
    println!(
        "  n={n} (completed {completed}/{attempted}, {:.1}% echoed within 3s)",
        100.0 * completed as f64 / attempted as f64
    );
    println!(
        "  median={:.1}  p90={:.1}  mean={mean:.1}  sd={sd:.1}  | per-seed median: mean={sm_mean:.1} sd={:.1} ({} seeds)",
        pct(all.clone(), 0.5),
        pct(all.clone(), 0.9),
        sm_var.sqrt(),
        seed_medians.len(),
    );
    println!(
        "  client fwd datagrams: {fwd_sends} ({:.2}/keystroke)   final srtt: {:.1} ms",
        fwd_sends as f64 / attempted as f64,
        srtt_sum / seeds as f64,
    );
}
