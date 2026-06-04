//! A synchronous, deterministic, virtual-time network simulator for [`SspCore`].
//!
//! Because the core is sans-IO, two of them plus a fake link form a fully
//! deterministic distributed system we can drive in a tight loop — no async, no
//! real clock, no wall-time. Same seed ⇒ identical execution, so any failure is
//! perfectly reproducible. This is the cheap, exhaustive layer of the testing
//! pyramid (mad-sim / turmoil come in later for the real QUIC transport).
//!
//! Node **A** runs `SspCore<L, R>` (sends `L`, receives `R`); node **B** is its
//! mirror `SspCore<R, L>`. Datagrams cross a link that can drop, delay, and
//! reorder them per [`SimConfig`].

use crate::clock::Millis;
use crate::core::{SspConfig, SspCore};
use crate::instruction::Instruction;
use crate::state::SyncState;

/// Link impairment + timing configuration for the simulator.
#[derive(Clone, Copy, Debug)]
pub struct SimConfig {
    /// Drop probability per datagram, in `[0.0, 1.0]`.
    pub loss: f64,
    /// Minimum one-way delay (ms).
    pub min_delay: Millis,
    /// Maximum one-way delay (ms); variability reorders datagrams.
    pub max_delay: Millis,
    /// RNG seed; identical seeds reproduce the run exactly.
    pub seed: u64,
    /// Protocol timing config handed to both cores.
    pub ssp: SspConfig,
}

impl Default for SimConfig {
    fn default() -> Self {
        Self {
            loss: 0.0,
            min_delay: 10,
            max_delay: 10,
            seed: 0x1234_5678_9ABC_DEF0,
            ssp: SspConfig::default(),
        }
    }
}

struct Rng(u64);
impl Rng {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
    fn next_f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }
    fn delay(&mut self, lo: Millis, hi: Millis) -> Millis {
        if hi <= lo {
            lo
        } else {
            lo + self.next_u64() % (hi - lo + 1)
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Dest {
    A,
    B,
}

struct InFlight {
    deliver: Millis,
    dest: Dest,
    inst: Instruction,
}

/// Two SSP cores connected through a simulated unreliable link.
pub struct NetworkSim<L: SyncState, R: SyncState> {
    a: SspCore<L, R>,
    b: SspCore<R, L>,
    now: Millis,
    in_flight: Vec<InFlight>,
    rng: Rng,
    cfg: SimConfig,
    /// Counters for assertions / observability.
    pub sent: u64,
    pub dropped: u64,
    pub delivered: u64,
}

impl<L: SyncState, R: SyncState> NetworkSim<L, R> {
    pub fn new(cfg: SimConfig) -> Self {
        Self {
            a: SspCore::with_config(0, cfg.ssp),
            b: SspCore::with_config(0, cfg.ssp),
            now: 0,
            in_flight: Vec::new(),
            rng: Rng(cfg.seed | 1),
            cfg,
            sent: 0,
            dropped: 0,
            delivered: 0,
        }
    }

    pub fn now(&self) -> Millis {
        self.now
    }

    /// Set node A's local state (the `L` that B should converge to).
    pub fn set_a_local(&mut self, state: L) {
        self.a.set_current_state(state);
    }

    /// Set node B's local state (the `R` that A should converge to).
    pub fn set_b_local(&mut self, state: R) {
        self.b.set_current_state(state);
    }

    /// What A currently believes B's state to be.
    pub fn a_view_of_b(&self) -> &R {
        self.a.remote_state()
    }

    /// What B currently believes A's state to be.
    pub fn b_view_of_a(&self) -> &L {
        self.b.remote_state()
    }

    fn schedule(&mut self, from: Dest, instrs: Vec<Instruction>) {
        for inst in instrs {
            self.sent += 1;
            if self.rng.next_f64() < self.cfg.loss {
                self.dropped += 1;
                continue;
            }
            let delay = self.rng.delay(self.cfg.min_delay, self.cfg.max_delay);
            let dest = match from {
                Dest::A => Dest::B,
                Dest::B => Dest::A,
            };
            self.in_flight.push(InFlight {
                deliver: self.now + delay,
                dest,
                inst,
            });
        }
    }

    /// Advance to the next event (a datagram delivery and/or a due tick) and
    /// process it. Returns `false` when there is genuinely nothing left to do.
    ///
    /// Note: in steady state both cores emit periodic keepalive acks, so this
    /// rarely returns `false`; use [`NetworkSim::run_until`] with a predicate.
    pub fn step(&mut self) -> bool {
        let aw = self.a.next_wakeup(self.now);
        let bw = self.b.next_wakeup(self.now);
        let dw = self.in_flight.iter().map(|f| f.deliver).min();

        let next = [aw, bw, dw].into_iter().flatten().min();
        let next = match next {
            Some(t) => t,
            None => return false,
        };
        self.now = self.now.max(next);

        // Deliver everything due at or before `now`.
        let now = self.now;
        let mut due = Vec::new();
        let mut i = 0;
        while i < self.in_flight.len() {
            if self.in_flight[i].deliver <= now {
                due.push(self.in_flight.swap_remove(i));
            } else {
                i += 1;
            }
        }
        for f in due {
            self.delivered += 1;
            match f.dest {
                Dest::A => self.a.recv(now, &f.inst),
                Dest::B => self.b.recv(now, &f.inst),
            }
        }

        // tick() self-gates on its timers, so calling both every step is safe.
        let a_out = self.a.tick(now);
        self.schedule(Dest::A, a_out);
        let b_out = self.b.tick(now);
        self.schedule(Dest::B, b_out);

        true
    }

    /// Step until `pred` holds (returns `true`) or `max_time` ms of virtual time
    /// elapse / the system goes quiescent (returns `false`).
    pub fn run_until<F: Fn(&Self) -> bool>(&mut self, pred: F, max_time: Millis) -> bool {
        // Cap iterations as a backstop against logic errors that fail to advance.
        let max_steps = 5_000_000usize;
        for _ in 0..max_steps {
            if pred(self) {
                return true;
            }
            if self.now > max_time {
                return false;
            }
            if !self.step() {
                return pred(self);
            }
        }
        pred(self)
    }
}
