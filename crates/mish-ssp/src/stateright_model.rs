//! Exhaustive **bounded** model checking of SSP convergence with [Stateright].
//!
//! [`crate::sim::NetworkSim`] is a *sampled* explorer: it drives the two real
//! cores through one pseudo-random schedule per seed. That can only ever *sample*
//! the space of loss/reorder/duplication orderings. This module turns it into an
//! *exhaustive* explorer: a Stateright [`Model`] whose nondeterminism is exactly
//! the schedule (which in-flight datagram to deliver next, whether to drop or
//! duplicate it, when each side mutates its local state), explored over **every**
//! interleaving up to a bounded scenario length.
//!
//! ## Why *bounded*, and why that's still a real theorem
//!
//! The real [`SspCore`] carries unbounded monotonic counters (`next_seq`, state
//! `num`s, absolute-ms timers) and `f64` RTT estimators, so there is no *finite
//! closed* state space to explore to exhaustion. We therefore bound the
//! **scenario length** — the number of local updates and protocol steps — via a
//! `steps_left` budget that strictly decreases on every transition. Within that
//! budget Stateright explores *all* schedule interleavings exhaustively. The
//! decreasing budget also makes the reachable graph a DAG, which is what
//! [`Property::eventually`] requires to be sound (it gives false negatives on
//! cyclic paths).
//!
//! The fingerprint ([`Hash`]/[`Eq`] on `SspCore`, defined in `core.rs`) is
//! *faithful* — it folds in every behavior-affecting field, including the `f64`
//! estimators by bit pattern — so deduplication never merges two genuinely
//! different cores. Nothing is silently collapsed.
//!
//! ## Two link models, two questions
//!
//! * **Adversarial** ([`SspModel::adversarial`]) — the link may drop, duplicate,
//!   and reorder freely, interleaved with local updates. We check **safety**:
//!     - `no_divergence`: a receiver never holds a value the sender never sent
//!       (a corrupt diff-apply would surface an out-of-alphabet state);
//!     - `bounded_received` / `bounded_sent`: the queues stay within their caps
//!       under sustained fault injection (the anti-DoS bound);
//!     - `can_converge` (a `sometimes` non-vacuity check: convergence is in fact
//!       reachable, so the harness isn't trivially satisfied).
//!
//! * **Fair** ([`SspModel::fair`]) — the link may reorder but every in-flight
//!   datagram is eventually delivered (fairness is baked into the action policy:
//!   while datagrams are pending, *delivering* them is the only move). We check
//!   **liveness**: `converge` — from every reachable state, both sides' views
//!   eventually equal the peer's latest state.
//!
//! Run with `cargo test -p mish-ssp stateright`.

use crate::core::{ResendMode, SspConfig, SspCore};
use crate::instruction::Instruction;
use crate::state::SyncState;
use crate::states::BytesState;
use stateright::{Checker, Model, Property};

/// Virtual-time advance per [`Act::Tick`]. Chosen larger than every timer in
/// [`model_cfg`] so a tick always flushes any due send/ack rather than no-op'ing.
const QUANTUM: u64 = 8;

/// A small, fast SSP config for the checker: tiny timers (so one [`Act::Tick`]
/// flushes), and small queue caps so the `bounded_*` properties have something
/// tight to bite on and the state space stays modest.
fn model_cfg() -> SspConfig {
    SspConfig {
        send_interval_min: 1,
        send_interval_max: 1,
        ack_interval: 2,
        ack_delay: 0,
        active_retry_timeout: 6,
        send_mindelay: 0,
        rto: 3,
        rto_srtt_factor: 1.5,
        max_sent_states: 6,
        max_received_states: 6,
        prospective_resend: true,
        resend_mode: ResendMode::Rto,
    }
}

/// Which core a datagram is destined for. A's outgoing instructions go to B and
/// vice versa (matching [`crate::sim::NetworkSim`]'s `Dest` flip).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Side {
    A,
    B,
}

/// One datagram in flight on the simulated link.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Msg {
    to: Side,
    inst: Instruction,
}

/// The whole distributed system: two real cores, the in-flight link, a logical
/// clock, and the remaining scenario budget. Both cores are `SspCore<BytesState,
/// BytesState>` — symmetric, so `a.remote_state()` is A's view of B and vice
/// versa.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Sys {
    a: SspCore<BytesState, BytesState>,
    b: SspCore<BytesState, BytesState>,
    /// In-flight datagrams. A `Vec` (not a set) so delivery *order* is a free
    /// choice — that's where reordering comes from.
    net: Vec<Msg>,
    clock: u64,
    /// Remaining local-state updates either side may still make.
    updates_left: u8,
    /// Strictly-decreasing scenario budget. Bounds the search and keeps the
    /// reachable graph acyclic (required for sound `eventually`).
    steps_left: u16,
}

/// A scheduler move.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum Act {
    /// A sets its local state to a value (byte tag from `alphabet_a`).
    UpdateA(u8),
    /// B sets its local state to a value (byte tag from `alphabet_b`).
    UpdateB(u8),
    /// Advance the clock by [`QUANTUM`] and tick both cores, enqueuing their
    /// output datagrams.
    Tick,
    /// Deliver the i-th in-flight datagram (and remove it).
    Deliver(usize),
    /// Drop the i-th in-flight datagram (adversarial link only).
    Drop(usize),
    /// Deliver a *copy* of the i-th datagram, leaving the original in flight —
    /// models duplication (adversarial link only).
    Dup(usize),
}

/// The model: a link discipline plus the scenario bounds.
struct SspModel {
    /// `true` ⇒ fair link (no drop/dup; pending datagrams must be delivered).
    fair: bool,
    /// Byte tags A may set as its local state.
    alphabet_a: Vec<u8>,
    /// Byte tags B may set as its local state.
    alphabet_b: Vec<u8>,
    /// Total local updates allowed across both sides.
    updates: u8,
    /// Initial `steps_left`.
    budget: u16,
    /// In the fair model, stop issuing new updates once `steps_left <= reserve`,
    /// so there is always enough budget left to drain to convergence.
    reserve: u16,
    cfg: SspConfig,
}

impl SspModel {
    fn adversarial() -> Self {
        SspModel {
            fair: false,
            alphabet_a: vec![1, 2],
            alphabet_b: vec![3],
            updates: 2,
            budget: 7,
            reserve: 0,
            cfg: model_cfg(),
        }
    }

    fn fair() -> Self {
        SspModel {
            fair: true,
            alphabet_a: vec![1, 2],
            alphabet_b: vec![3],
            updates: 2,
            budget: 24,
            reserve: 10,
            cfg: model_cfg(),
        }
    }
}

fn bytes(tag: u8) -> BytesState {
    BytesState::new(vec![tag])
}

/// Whether `core`'s local state already equals the single-byte value `tag` (so we
/// can skip generating a no-op update).
fn local_is(core: &SspCore<BytesState, BytesState>, tag: u8) -> bool {
    core.current_state().as_slice() == [tag]
}

/// Whether `v` is a legal synchronized value: the agreed initial (empty) state,
/// or a single-byte tag from `alpha`. A diff-apply bug that fabricated a state
/// the sender never produced would land *outside* this set.
fn in_alphabet(v: &BytesState, alpha: &[u8]) -> bool {
    let s = v.as_slice();
    s.is_empty() || (s.len() == 1 && alpha.contains(&s[0]))
}

/// Both sides' views match the peer's current local state.
fn converged(s: &Sys) -> bool {
    s.a.remote_state().equals(s.b.current_state()) && s.b.remote_state().equals(s.a.current_state())
}

/// Deliver one datagram into its destination core at the current clock.
fn deliver(s: &mut Sys, m: &Msg) {
    let now = s.clock;
    match m.to {
        Side::A => s.a.recv(now, &m.inst),
        Side::B => s.b.recv(now, &m.inst),
    }
}

impl Model for SspModel {
    type State = Sys;
    type Action = Act;

    fn init_states(&self) -> Vec<Self::State> {
        vec![Sys {
            a: SspCore::with_config(0, self.cfg),
            b: SspCore::with_config(0, self.cfg),
            net: Vec::new(),
            clock: 0,
            updates_left: self.updates,
            steps_left: self.budget,
        }]
    }

    fn actions(&self, s: &Self::State, acts: &mut Vec<Self::Action>) {
        if s.steps_left == 0 {
            return; // terminal: budget exhausted
        }

        if self.fair {
            // Fairness: while datagrams are pending, the *only* moves are to
            // deliver them (in any order). Nothing can starve in flight.
            if !s.net.is_empty() {
                for i in 0..s.net.len() {
                    acts.push(Act::Deliver(i));
                }
                return;
            }
            // Link is quiet: tick to drive the next round, and (early enough that
            // we can still drain) optionally apply a local update.
            acts.push(Act::Tick);
            if s.updates_left > 0 && s.steps_left > self.reserve {
                push_updates(self, s, acts);
            }
            return;
        }

        // Adversarial: updates, ticks, and per-datagram deliver/drop/dup all
        // interleave freely.
        if s.updates_left > 0 {
            push_updates(self, s, acts);
        }
        acts.push(Act::Tick);
        for i in 0..s.net.len() {
            acts.push(Act::Deliver(i));
            acts.push(Act::Drop(i));
            acts.push(Act::Dup(i));
        }
    }

    fn next_state(&self, last: &Self::State, action: Self::Action) -> Option<Self::State> {
        let mut s = last.clone();
        s.steps_left -= 1;
        match action {
            Act::UpdateA(v) => {
                s.a.set_current_state(bytes(v));
                s.updates_left -= 1;
            }
            Act::UpdateB(v) => {
                s.b.set_current_state(bytes(v));
                s.updates_left -= 1;
            }
            Act::Tick => {
                s.clock += QUANTUM;
                let now = s.clock;
                for inst in s.a.tick(now) {
                    s.net.push(Msg { to: Side::B, inst });
                }
                for inst in s.b.tick(now) {
                    s.net.push(Msg { to: Side::A, inst });
                }
            }
            Act::Deliver(i) => {
                let m = s.net.remove(i);
                deliver(&mut s, &m);
            }
            Act::Drop(i) => {
                s.net.remove(i);
            }
            Act::Dup(i) => {
                let m = s.net[i].clone();
                deliver(&mut s, &m);
            }
        }
        Some(s)
    }

    fn properties(&self) -> Vec<Property<Self>> {
        if self.fair {
            vec![
                // Liveness: every behavior converges (sound here — the budget
                // makes the graph acyclic, and fairness forces delivery).
                Property::eventually("converge", |_, s| converged(s)),
                // Safety still holds on the fair link too.
                Property::always("no_divergence", no_divergence),
            ]
        } else {
            vec![
                Property::always("no_divergence", no_divergence),
                Property::always("bounded_received", bounded_received),
                Property::always("bounded_sent", bounded_sent),
                // Non-vacuity: convergence is actually reachable under faults.
                Property::sometimes("can_converge", |_, s| converged(s)),
            ]
        }
    }
}

fn push_updates(m: &SspModel, s: &Sys, acts: &mut Vec<Act>) {
    for &v in &m.alphabet_a {
        if !local_is(&s.a, v) {
            acts.push(Act::UpdateA(v));
        }
    }
    for &v in &m.alphabet_b {
        if !local_is(&s.b, v) {
            acts.push(Act::UpdateB(v));
        }
    }
}

/// Neither side ever believes the peer holds a value the peer never produced.
fn no_divergence(m: &SspModel, s: &Sys) -> bool {
    in_alphabet(s.a.remote_state(), &m.alphabet_b) && in_alphabet(s.b.remote_state(), &m.alphabet_a)
}

/// Received-state queues stay within the cap (+1: the guard rejects only *after*
/// the queue exceeds the cap — see `SspCore::recv`).
fn bounded_received(m: &SspModel, s: &Sys) -> bool {
    let cap = m.cfg.max_received_states + 1;
    s.a.received_state_count() <= cap && s.b.received_state_count() <= cap
}

/// Sent-state queues stay within the cap.
fn bounded_sent(m: &SspModel, s: &Sys) -> bool {
    let cap = m.cfg.max_sent_states;
    s.a.sent_state_count() <= cap && s.b.sent_state_count() <= cap
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exhaustive safety check over an adversarial (lossy / reordering /
    /// duplicating) link: no divergence, bounded memory, and convergence
    /// reachable — across every schedule of length ≤ `budget`.
    #[test]
    fn safety_under_adversarial_link() {
        let checker = SspModel::adversarial().checker().spawn_bfs().join();
        eprintln!(
            "[adversarial] states={} unique={} max_depth={}",
            checker.state_count(),
            checker.unique_state_count(),
            checker.max_depth(),
        );
        checker.assert_properties();
    }

    /// Exhaustive liveness check over a fair (reordering but lossless) link:
    /// every reachable state converges, across every delivery order.
    #[test]
    fn liveness_under_fair_link() {
        let checker = SspModel::fair().checker().spawn_bfs().join();
        eprintln!(
            "[fair] states={} unique={} max_depth={}",
            checker.state_count(),
            checker.unique_state_count(),
            checker.max_depth(),
        );
        checker.assert_properties();
    }
}
