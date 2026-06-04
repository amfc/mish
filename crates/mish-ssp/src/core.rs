//! The sans-IO State Synchronization Protocol core.
//!
//! This is a faithful Rust port of mosh's `TransportSender` (outgoing) +
//! `Transport` receiver logic (`network/transportsender-impl.h`,
//! `network/networktransport-impl.h`), collapsed into one deterministic state
//! machine per connection direction-pair.
//!
//! # Design: sans-IO
//!
//! [`SspCore`] performs **no I/O and reads no clock**. The caller drives it:
//!
//! * Mutate the local state with [`SspCore::set_current_state`].
//! * Feed received datagrams via [`SspCore::recv`].
//! * Call [`SspCore::tick`] when due; it returns zero or more [`Instruction`]s
//!   for the caller to serialize and put on the wire.
//! * Ask [`SspCore::next_wakeup`] when to tick next.
//!
//! Because time is an argument, the whole protocol is replayable and can be
//! driven by a virtual clock in simulation tests.
//!
//! # The algorithm in one paragraph
//!
//! There is no retransmit queue. The sender keeps a list of timestamped states
//! it has sent (`sent_states`): the front is the latest state the peer has
//! *acknowledged*, the back is the latest state sent. Somewhere in between is
//! the `assumed_receiver_state` — the newest unacked state recent enough to give
//! the peer the benefit of the doubt. Each send computes
//! `current_state.diff_from(assumed_receiver_state)` — so a lost datagram simply
//! means the next send re-diffs from further back and naturally includes the
//! missing changes. The receiver applies diffs idempotently, keyed by the
//! `old_num`/`new_num` chain, and piggy-backs acks.

use std::collections::VecDeque;

use crate::clock::{Millis, NEVER};
use crate::instruction::{Instruction, PROTOCOL_VERSION};
use crate::state::SyncState;

/// Tunable protocol timing parameters (all milliseconds). Defaults mirror mosh.
#[derive(Clone, Copy, Debug)]
pub struct SspConfig {
    /// Minimum gap between data frames (mosh `SEND_INTERVAL_MIN`).
    pub send_interval_min: Millis,
    /// Maximum gap between data frames (mosh `SEND_INTERVAL_MAX`).
    pub send_interval_max: Millis,
    /// Interval between empty keepalive acks (mosh `ACK_INTERVAL`).
    pub ack_interval: Millis,
    /// Delay before sending a delayed ack (mosh `ACK_DELAY`).
    pub ack_delay: Millis,
    /// Stop retrying at frame rate after this much silence (mosh `ACTIVE_RETRY_TIMEOUT`).
    pub active_retry_timeout: Millis,
    /// Time to collect local input before sending (mosh `SEND_MINDELAY`).
    pub send_mindelay: Millis,
    /// Retransmission timeout estimate. Mosh derives this from RTT; until the
    /// datagram-layer RTT estimator lands we use a fixed value. Governs how long
    /// an unacked state retains "benefit of the doubt".
    pub rto: Millis,
    /// Cap on retained sent states before middle entries are dropped.
    pub max_sent_states: usize,
    /// Cap on retained received states.
    pub max_received_states: usize,
}

impl Default for SspConfig {
    fn default() -> Self {
        Self {
            send_interval_min: 20,
            send_interval_max: 250,
            ack_interval: 3000,
            ack_delay: 100,
            active_retry_timeout: 10_000,
            send_mindelay: 8,
            rto: 1000,
            max_sent_states: 32,
            max_received_states: 1024,
        }
    }
}

#[derive(Clone, Debug)]
struct Timestamped<S> {
    timestamp: Millis,
    num: u64,
    state: S,
}

/// Jacobson/Karels SRTT/RTTVAR estimator (RFC 6298 / mosh's `Connection`).
#[derive(Clone, Debug)]
struct Rtt {
    srtt: f64,
    rttvar: f64,
    initialized: bool,
}

impl Rtt {
    fn new() -> Self {
        Self {
            srtt: 1000.0,
            rttvar: 500.0,
            initialized: false,
        }
    }

    fn sample(&mut self, r: Millis) {
        let r = r as f64;
        if !self.initialized {
            self.srtt = r;
            self.rttvar = r / 2.0;
            self.initialized = true;
        } else {
            const ALPHA: f64 = 1.0 / 8.0;
            const BETA: f64 = 1.0 / 4.0;
            self.rttvar = (1.0 - BETA) * self.rttvar + BETA * (self.srtt - r).abs();
            self.srtt = (1.0 - ALPHA) * self.srtt + ALPHA * r;
        }
    }

    /// Retransmission timeout estimate (ms), before clamping to config bounds.
    fn rto(&self) -> f64 {
        self.srtt + 4.0 * self.rttvar
    }
}

/// One direction-pair of the State Synchronization Protocol.
///
/// `L` is the local state we send to the peer; `R` is the remote state we
/// receive. (In mosh, a client is `SspCore<UserStream, Complete>` and the server
/// is the mirror image `SspCore<Complete, UserStream>`.)
pub struct SspCore<L: SyncState, R: SyncState> {
    cfg: SspConfig,

    // ---- Sender half (outgoing `L`) ----
    current_state: L,
    /// front = last acked-by-peer state, back = last sent state.
    sent_states: VecDeque<Timestamped<L>>,
    /// Index into `sent_states` of the assumed receiver state.
    assumed_receiver_idx: usize,
    next_ack_time: Millis,
    next_send_time: Millis,
    /// Highest remote state number we've received (what we will ack).
    ack_num: u64,
    /// We owe the peer a prompt (delayed) ack for data it sent.
    pending_data_ack: bool,
    /// Last time we received a *new* remote state.
    last_heard: Millis,
    /// Time of first pending change to `current_state`; `None` when in sync.
    mindelay_clock: Option<Millis>,

    // ---- Receiver half (incoming `R`) ----
    /// Sorted ascending by num; front = oldest retained, back = newest.
    received_states: VecDeque<Timestamped<R>>,

    // ---- RTT estimation ----
    rtt: Rtt,
    /// Most recent timestamp received from the peer, and when we received it, so
    /// we can echo it adjusted for the time we held it.
    saved_timestamp: Option<u16>,
    saved_timestamp_received_at: Millis,

    // ---- Shutdown handshake ----
    /// We have initiated a clean shutdown (sending num = SHUTDOWN_NUM).
    shutdown_in_progress: bool,
    /// The peer has acknowledged our shutdown (ack_num == SHUTDOWN_NUM).
    shutdown_acked: bool,
    /// The peer is shutting down (we received new_num == SHUTDOWN_NUM).
    peer_shutdown: bool,
}

impl<L: SyncState, R: SyncState> SspCore<L, R> {
    /// Create a core. Both peers implicitly agree on the num-0 initial states.
    pub fn new(now: Millis) -> Self {
        Self::with_config(now, SspConfig::default())
    }

    pub fn with_config(now: Millis, cfg: SspConfig) -> Self {
        let mut sent_states = VecDeque::new();
        sent_states.push_back(Timestamped {
            timestamp: now,
            num: 0,
            state: L::new_initial(),
        });
        let mut received_states = VecDeque::new();
        received_states.push_back(Timestamped {
            timestamp: now,
            num: 0,
            state: R::new_initial(),
        });
        Self {
            cfg,
            current_state: L::new_initial(),
            sent_states,
            assumed_receiver_idx: 0,
            next_ack_time: now,
            next_send_time: now,
            ack_num: 0,
            pending_data_ack: false,
            last_heard: 0,
            mindelay_clock: None,
            received_states,
            rtt: Rtt::new(),
            saved_timestamp: None,
            saved_timestamp_received_at: 0,
            shutdown_in_progress: false,
            shutdown_acked: false,
            peer_shutdown: false,
        }
    }

    // ----- Application-facing accessors -----

    /// Replace the local state to be synchronized to the peer.
    pub fn set_current_state(&mut self, state: L) {
        self.current_state = state;
    }

    /// Mutable access to the local state (mark dirty by mutating in place).
    pub fn current_state_mut(&mut self) -> &mut L {
        &mut self.current_state
    }

    pub fn current_state(&self) -> &L {
        &self.current_state
    }

    /// The latest remote state received from the peer.
    pub fn remote_state(&self) -> &R {
        &self.received_states.back().expect("never empty").state
    }

    /// The num of the latest remote state (monotonically non-decreasing).
    pub fn remote_state_num(&self) -> u64 {
        self.received_states.back().expect("never empty").num
    }

    /// Smoothed round-trip time estimate in milliseconds (the configured RTO
    /// until the first RTT sample arrives). Drives adaptive predictive echo.
    pub fn srtt_ms(&self) -> f64 {
        if self.rtt.initialized {
            self.rtt.srtt
        } else {
            self.cfg.rto as f64
        }
    }

    /// Begin a clean shutdown: subsequent ticks send `SHUTDOWN_NUM` instructions
    /// until the peer acknowledges (see [`SspCore::is_shutdown_acked`]).
    pub fn start_shutdown(&mut self) {
        if !self.shutdown_in_progress {
            self.shutdown_in_progress = true;
            self.next_send_time = 0; // fire on the next tick
        }
    }

    pub fn shutdown_in_progress(&self) -> bool {
        self.shutdown_in_progress
    }

    /// The peer has acknowledged our shutdown — safe to close.
    pub fn is_shutdown_acked(&self) -> bool {
        self.shutdown_acked
    }

    /// The peer has begun shutting down (we should ack and close).
    pub fn peer_is_shutting_down(&self) -> bool {
        self.peer_shutdown
    }

    fn emit_shutdown(&mut self, now: Millis, out: &mut Vec<Instruction>) {
        let front = self.sent_states.front().expect("never empty").num;
        out.push(Instruction {
            protocol_version: PROTOCOL_VERSION,
            old_num: self.assumed().num,
            new_num: crate::instruction::SHUTDOWN_NUM,
            ack_num: self.ack_num,
            throwaway_num: front,
            diff: Vec::new(),
            timestamp: (now & 0xFFFF) as u16,
            timestamp_reply: self.timestamp_reply(now),
        });
    }

    /// Whether everything we've produced has been acknowledged by the peer.
    pub fn is_synced(&self) -> bool {
        let back = self.sent_states.back().expect("never empty");
        self.current_state.equals(&back.state)
            && self.sent_states.front().expect("never empty").num == back.num
    }

    // ----- Timing -----

    fn send_interval(&self) -> Millis {
        // Aim for ~2 frames per RTT, clamped to the configured bounds. Falls back
        // to the minimum interval until we have an RTT sample.
        if self.rtt.initialized {
            (self.rtt.srtt / 2.0).ceil() as Millis
        } else {
            self.cfg.send_interval_min
        }
        .clamp(self.cfg.send_interval_min, self.cfg.send_interval_max)
    }

    fn timeout(&self) -> Millis {
        // RTT-derived RTO, clamped so it never exceeds the configured rto (which
        // acts as the conservative upper bound) and stays above a small floor.
        if self.rtt.initialized {
            (self.rtt.rto().ceil() as Millis).clamp(50, self.cfg.rto)
        } else {
            self.cfg.rto
        }
    }

    /// The assumed receiver state: newest unacked sent state recent enough to
    /// assume delivered. Reverts toward the acked front once the RTO elapses,
    /// which is what triggers retransmission of lost data.
    fn update_assumed_receiver_state(&mut self, now: Millis) {
        self.assumed_receiver_idx = 0;
        let window = self.timeout() + self.cfg.ack_delay;
        for i in 1..self.sent_states.len() {
            let age = now.saturating_sub(self.sent_states[i].timestamp);
            if age < window {
                self.assumed_receiver_idx = i;
            } else {
                break;
            }
        }
    }

    /// Drop information already known to the acked receiver state, bounding memory.
    fn rationalize_states(&mut self) {
        let known = self.sent_states.front().expect("never empty").state.clone();
        self.current_state.subtract(&known);
        for s in self.sent_states.iter_mut() {
            s.state.subtract(&known);
        }
    }

    fn assumed(&self) -> &Timestamped<L> {
        &self.sent_states[self.assumed_receiver_idx]
    }

    fn calculate_timers(&mut self, now: Millis) {
        self.update_assumed_receiver_state(now);
        self.rationalize_states();

        if self.pending_data_ack && self.next_ack_time > now + self.cfg.ack_delay {
            self.next_ack_time = now + self.cfg.ack_delay;
        }

        let back = self.sent_states.back().expect("never empty");
        let front = self.sent_states.front().expect("never empty");
        let active = self.last_heard + self.cfg.active_retry_timeout > now;

        if !self.current_state.equals(&back.state) {
            // We have new local data not yet sent.
            if self.mindelay_clock.is_none() {
                self.mindelay_clock = Some(now);
            }
            let mindelay = self.mindelay_clock.unwrap() + self.cfg.send_mindelay;
            self.next_send_time = mindelay.max(back.timestamp + self.send_interval());
        } else if !self.current_state.equals(&self.assumed().state) && active {
            // Sent, but not yet (assumed) delivered — retransmit at frame rate.
            self.next_send_time = back.timestamp + self.send_interval();
            if let Some(mc) = self.mindelay_clock {
                self.next_send_time = self.next_send_time.max(mc + self.cfg.send_mindelay);
            }
        } else if !self.current_state.equals(&front.state) && active {
            // Unacked but assumed-delivered: wait a full timeout before re-poking.
            self.next_send_time = back.timestamp + self.timeout() + self.cfg.ack_delay;
        } else {
            self.next_send_time = NEVER;
        }

        if self.ack_num == u64::MAX {
            // shutdown special-case (reserved)
            self.next_ack_time = back.timestamp + self.send_interval();
        }
    }

    /// Absolute time of the next event, or [`None`] if there is nothing to do.
    pub fn next_wakeup(&mut self, now: Millis) -> Option<Millis> {
        if self.shutdown_in_progress {
            return Some(self.next_send_time);
        }
        self.calculate_timers(now);
        let next = self.next_ack_time.min(self.next_send_time);
        if next == NEVER {
            None
        } else {
            Some(next)
        }
    }

    /// Milliseconds to wait until the next [`SspCore::tick`] is due (0 = now,
    /// [`None`] = nothing pending).
    pub fn wait_time(&mut self, now: Millis) -> Option<Millis> {
        self.next_wakeup(now).map(|w| w.saturating_sub(now))
    }

    // ----- Sending -----

    /// Run the protocol's send logic. Returns instructions to put on the wire
    /// (usually 0 or 1). Call when [`SspCore::next_wakeup`] says it's due (the
    /// driver may also call it eagerly — it self-gates on the timers).
    pub fn tick(&mut self, now: Millis) -> Vec<Instruction> {
        // Shutdown takes over the send loop: resend a SHUTDOWN_NUM instruction at
        // the frame rate until the peer acknowledges it.
        if self.shutdown_in_progress {
            let mut out = Vec::new();
            if now >= self.next_send_time {
                self.emit_shutdown(now, &mut out);
                self.next_send_time = now + self.send_interval();
            }
            return out;
        }

        self.calculate_timers(now);

        if now < self.next_ack_time && now < self.next_send_time {
            return Vec::new();
        }

        let diff = self.current_state.diff_from(&self.assumed().state);

        let mut out = Vec::new();
        if diff.is_empty() {
            if now >= self.next_ack_time {
                self.send_empty_ack(now, &mut out);
                self.mindelay_clock = None;
            }
            if now >= self.next_send_time {
                self.next_send_time = NEVER;
                self.mindelay_clock = None;
            }
        } else if now >= self.next_send_time || now >= self.next_ack_time {
            self.send_to_receiver(now, diff, &mut out);
            self.mindelay_clock = None;
        }
        out
    }

    fn send_to_receiver(&mut self, now: Millis, diff: Vec<u8>, out: &mut Vec<Instruction>) {
        let back_num = self.sent_states.back().expect("never empty").num;
        let back_eq = self
            .current_state
            .equals(&self.sent_states.back().expect("never empty").state);

        let new_num = if back_eq { back_num } else { back_num + 1 };

        if new_num == back_num {
            self.sent_states.back_mut().expect("never empty").timestamp = now;
        } else {
            self.add_sent_state(now, new_num);
        }

        self.emit(now, diff, new_num, out);

        self.assumed_receiver_idx = self.sent_states.len() - 1;
        self.next_ack_time = now + self.cfg.ack_interval;
        self.next_send_time = NEVER;
    }

    fn send_empty_ack(&mut self, now: Millis, out: &mut Vec<Instruction>) {
        let new_num = self.sent_states.back().expect("never empty").num + 1;
        self.add_sent_state(now, new_num);
        self.emit(now, Vec::new(), new_num, out);
        self.next_ack_time = now + self.cfg.ack_interval;
        self.next_send_time = NEVER;
    }

    /// Build the timestamp echo for an outgoing instruction: the peer's last
    /// timestamp plus how long we've held it (so the peer can subtract its own
    /// processing/queueing time when computing RTT).
    fn timestamp_reply(&self, now: Millis) -> Option<u16> {
        self.saved_timestamp.map(|ts| {
            let held = now.saturating_sub(self.saved_timestamp_received_at) as u16;
            ts.wrapping_add(held)
        })
    }

    /// Push `current_state` as a newly-sent state, capping the queue.
    fn add_sent_state(&mut self, now: Millis, num: u64) {
        self.sent_states.push_back(Timestamped {
            timestamp: now,
            num,
            state: self.current_state.clone(),
        });
        if self.sent_states.len() > self.cfg.max_sent_states {
            // Drop a state from the middle (keep the acked front and recent tail),
            // mirroring mosh's add_sent_state.
            let remove = self.sent_states.len() - 16;
            self.sent_states.remove(remove);
        }
    }

    fn emit(&mut self, now: Millis, diff: Vec<u8>, new_num: u64, out: &mut Vec<Instruction>) {
        // Fragmentation/MTU-splitting and length-disguising chaff are handled one
        // layer up (the session Driver fragments by transport MTU).
        out.push(Instruction {
            protocol_version: PROTOCOL_VERSION,
            old_num: self.assumed().num,
            new_num,
            ack_num: self.ack_num,
            throwaway_num: self.sent_states.front().expect("never empty").num,
            diff,
            timestamp: (now & 0xFFFF) as u16,
            timestamp_reply: self.timestamp_reply(now),
        });
        self.pending_data_ack = false;
    }

    // ----- Receiving -----

    /// Process one received instruction: update acks, then apply the diff to the
    /// referenced remote state if it is new.
    pub fn recv(&mut self, now: Millis, inst: &Instruction) {
        if inst.protocol_version != PROTOCOL_VERSION {
            return;
        }

        // 0. RTT bookkeeping: take a round-trip sample from our echoed timestamp,
        //    and remember the peer's timestamp so we can echo it back.
        if let Some(reply) = inst.timestamp_reply {
            let sample = (now as u16).wrapping_sub(reply) as Millis;
            // Guard against absurd samples from clock skew / wraparound.
            if sample < 60_000 {
                self.rtt.sample(sample);
            }
        }
        self.saved_timestamp = Some(inst.timestamp);
        self.saved_timestamp_received_at = now;

        // Shutdown handshake.
        if inst.ack_num == crate::instruction::SHUTDOWN_NUM {
            // The peer acknowledged our shutdown.
            self.shutdown_acked = true;
        }
        if inst.new_num == crate::instruction::SHUTDOWN_NUM {
            // The peer is shutting down; record it and ack it (our outgoing
            // ack_num becomes SHUTDOWN_NUM) — don't apply as a normal state.
            self.peer_shutdown = true;
            self.ack_num = crate::instruction::SHUTDOWN_NUM;
            self.last_heard = now;
            self.pending_data_ack = true;
            return;
        }

        // 1. The peer told us what it has received from us → advance our acks.
        self.process_acknowledgment_through(inst.ack_num);

        // 2. Locate the reference state this diff builds on. If we don't have it,
        //    drop the instruction. This enforces idempotency/replay-safety.
        let reference = match self.received_states.iter().find(|s| s.num == inst.old_num) {
            Some(r) => r.clone(),
            None => return,
        };

        // 3. GC received states the sender no longer needs.
        self.process_throwaway_until(inst.throwaway_num);

        // 4. Reject if our receive queue is full (anti-DoS; mosh quenches here).
        if self.received_states.len() > self.cfg.max_received_states {
            return;
        }

        // 5. Ignore duplicates / already-known states (idempotency).
        if self.received_states.iter().any(|s| s.num == inst.new_num) {
            return;
        }

        // 6. Apply the diff to a copy of the reference to build the new state.
        let mut new_state = reference.state.clone();
        if inst.has_diff() {
            new_state.apply_diff(&inst.diff);
        }
        let entry = Timestamped {
            timestamp: now,
            num: inst.new_num,
            state: new_state,
        };

        // 7. Insert in num-sorted order. If something newer already exists, this
        //    is an out-of-order arrival: insert but don't advance the ack.
        if let Some(pos) = self.received_states.iter().position(|s| s.num > entry.num) {
            self.received_states.insert(pos, entry);
            return;
        }

        // Newest state: append and acknowledge it.
        self.received_states.push_back(entry);
        let newest = self.received_states.back().expect("never empty").num;
        self.ack_num = newest;
        self.last_heard = now;
        if inst.has_diff() {
            self.pending_data_ack = true;
        }
    }

    /// Drop sent states the peer has acknowledged. Front becomes the acked state.
    fn process_acknowledgment_through(&mut self, ack_num: u64) {
        while self.sent_states.len() > 1
            && self.sent_states.front().expect("never empty").num < ack_num
        {
            self.sent_states.pop_front();
        }
    }

    /// Drop received states older than the sender's `throwaway_num`.
    fn process_throwaway_until(&mut self, throwaway_num: u64) {
        while self.received_states.len() > 1
            && self.received_states.front().expect("never empty").num < throwaway_num
        {
            self.received_states.pop_front();
        }
    }
}
