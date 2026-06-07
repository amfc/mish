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
    /// Upper bound (and pre-RTT fallback) for the retransmission timeout. The RTO
    /// is derived from the RTT estimate (see [`SspCore::set_transport_rtt`]) and
    /// clamped to `[RTO_FLOOR, rto]`. Governs how long an unacked state retains
    /// "benefit of the doubt".
    pub rto: Millis,
    /// When driving the RTO from the transport's base (minimum) RTT,
    /// `RTO = rto_srtt_factor · base_rtt` (clamped to `[RTO_FLOOR, rto]`). 1.5×
    /// gives loss-detection margin over the path RTT without the reorder-inflated
    /// blowup of `srtt + 4·rttvar`. Unused for the internal Jacobson path (no
    /// transport RTT), which keeps `srtt + 4·rttvar`.
    pub rto_srtt_factor: f64,
    /// Cap on retained sent states before middle entries are dropped.
    pub max_sent_states: usize,
    /// Cap on retained received states.
    pub max_received_states: usize,
    /// Enable the prophylactic-resend loss-recovery optimization (mosh's
    /// `attempt_prospective_resend_optimization`). On by default; exposed mainly
    /// so benchmarks can A/B its effect.
    pub prospective_resend: bool,
    /// How fast to retransmit data that has been sent but not yet acked. See
    /// [`ResendMode`]. Default [`ResendMode::FrameRateOnLoss`].
    pub resend_mode: ResendMode,
}

/// Retransmit cadence for sent-but-unacked data (the BRUTAL keyboard-tail lever).
///
/// When a keystroke is sent, the sender gives it benefit-of-the-doubt for one
/// RTO. If no ack arrives, that RTO has been *spent detecting the loss*; the
/// question is how fast to retry afterwards. Retrying at the full RTO each time
/// (`Rto`) is what fattens the BRUTAL p90 tail — a keystroke caught in a deep
/// burst eats several whole RTOs, and BRUTAL's reorder inflates the RTO on top.
/// See `PERFORMANCE.md`'s residual section and `examples/tail_probe.rs`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResendMode {
    /// Wait a full `timeout()` (RTO) + `ack_delay` between every retransmit.
    /// Lowest bandwidth, fattest recovery tail under burst loss.
    Rto,
    /// Always re-poke at the data-frame interval. Thins the tail but over-sends
    /// in the common *no-loss* case, which raises the median (more packets ⇒ more
    /// burst exposure). Diagnostic only — see the probe.
    FrameRate,
    /// Loss-gated: behave like [`Rto`] until the first RTO elapses without an ack
    /// (loss confirmed), then retry at the frame interval until the data is acked,
    /// reverting to optimistic once back in sync. Thins the tail in the *sim*'s deep
    /// synthetic bursts, but **did not** move the live-bench BRUTAL tail (whose
    /// keystrokes mostly need a single retransmit) — kept as an A/B knob, not the
    /// default. See `PERFORMANCE.md`.
    FrameRateOnLoss,
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
            rto_srtt_factor: 1.5,
            max_sent_states: 32,
            max_received_states: 1024,
            prospective_resend: true,
            // Stays `Rto`: the `FrameRateOnLoss` experiment thinned the *sim* tail
            // but not the live-bench tail (real BRUTAL keystrokes mostly need one
            // retransmit, so faster *subsequent* retries don't help — the win is in
            // the first-detection RTO instead). See `PERFORMANCE.md`'s residual.
            resend_mode: ResendMode::Rto,
        }
    }
}

impl SspConfig {
    /// Apply optional experimental overrides from the environment. No-op unless
    /// the vars are set, so default behavior is unchanged. Used to A/B recovery
    /// timing on the live bench stack (see `examples/tail_probe.rs` and
    /// `PERFORMANCE.md`'s residual section): `MISH_SSP_RTO` caps the
    /// retransmission timeout (ms), `MISH_SSP_SENDMAX` the data-frame interval.
    pub fn with_env_overrides(mut self) -> Self {
        if let Some(v) = std::env::var("MISH_SSP_RTO").ok().and_then(|s| s.parse().ok()) {
            self.rto = v;
        }
        if let Some(v) = std::env::var("MISH_SSP_SENDMAX").ok().and_then(|s| s.parse().ok()) {
            self.send_interval_max = v;
        }
        if let Some(v) = std::env::var("MISH_SSP_RTO_FACTOR").ok().and_then(|s| s.parse().ok()) {
            self.rto_srtt_factor = v;
        }
        if let Ok(v) = std::env::var("MISH_SSP_RESEND") {
            self.resend_mode = match v.as_str() {
                "rto" => ResendMode::Rto,
                "frame" => ResendMode::FrameRate,
                "frame_on_loss" => ResendMode::FrameRateOnLoss,
                _ => self.resend_mode,
            };
        }
        self
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
///
/// `Clone` is provided only under `cfg(test)` — the bounded model checker
/// (`crate::stateright_model`) snapshots whole cores to fork the schedule; normal
/// builds don't clone a live core.
#[cfg_attr(test, derive(Clone))]
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
    /// Monotonic per-packet sequence stamped on every emitted instruction (mosh's
    /// `Packet::seq`). Used by the *peer's* receiver as a reorder guard for RTT.
    next_seq: u64,
    /// True once an RTO has elapsed without the latest data being acked (loss
    /// confirmed for the current outstanding state). Gates `FrameRateOnLoss`'s
    /// switch to frame-rate retries; cleared when everything we sent is acked.
    in_loss_recovery: bool,
    /// The transport's smoothed RTT (ms), injected via
    /// [`set_transport_rtt`](SspCore::set_transport_rtt). When `Some`, it drives
    /// the send cadence in place of the internal timestamp estimator.
    transport_srtt_ms: Option<f64>,
    /// Running minimum of the injected transport RTT (ms) — an estimate of the
    /// link's *base* RTT. The RTO is derived from this rather than the smoothed
    /// RTT, because under burst loss/reorder even QUIC's smoothed RTT inflates
    /// (loss + ack-delay), whereas the minimum stays near the true path RTT. That
    /// keeps loss detection fast under BRUTAL yet still scales on a genuinely slow
    /// link (where the minimum is itself large). The fix for the keyboard tail.
    transport_min_rtt_ms: Option<f64>,

    // ---- Receiver half (incoming `R`) ----
    /// Sorted ascending by num; front = oldest retained, back = newest.
    received_states: VecDeque<Timestamped<R>>,
    /// Highest peer `seq` seen + 1 (mosh's `expected_receiver_seq`). A received
    /// instruction with `seq` below this is reordered/late and is excluded from
    /// RTT sampling (its echoed timestamp is stale), though its state is still
    /// applied. This keeps reordered acks from inflating the RTO. See [`recv`].
    expected_recv_seq: u64,

    // ---- RTT estimation ----
    rtt: Rtt,
    /// Running minimum of the (seq-guarded) internal RTT *samples* — our own
    /// `min_rtt`, an estimate of the base path RTT. Loss/reorder/jitter only ever
    /// *add* to a sample, so they never lower the minimum; it tracks the true RTT.
    /// The RTO is derived from this (× [`SspConfig::rto_srtt_factor`]) rather than
    /// `srtt + 4·rttvar`, which inflates under burst loss and fattens the keyboard
    /// tail. This is the self-contained (no-transport) form of the tail fix, and
    /// the one the deterministic sim exercises.
    internal_min_rtt_ms: Option<f64>,
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
            next_seq: 0,
            in_loss_recovery: false,
            transport_srtt_ms: None,
            transport_min_rtt_ms: None,
            received_states,
            expected_recv_seq: 0,
            rtt: Rtt::new(),
            internal_min_rtt_ms: None,
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
    /// Prefers the transport's estimate when one has been injected.
    pub fn srtt_ms(&self) -> f64 {
        if let Some(s) = self.transport_srtt_ms {
            s
        } else if self.rtt.initialized {
            self.rtt.srtt
        } else {
            self.cfg.rto as f64
        }
    }

    /// Inject the transport's smoothed RTT (ms), which then drives the send
    /// cadence and RTO instead of the internal timestamp sampler. QUIC's estimate
    /// is robust to the reordering that inflates our own `rttvar` (and thus the
    /// RTO and the BRUTAL keyboard tail — see `PERFORMANCE.md`). `None` reverts to
    /// the internal estimator (the path the sim/tests exercise). The driver calls
    /// this each loop with `transport.rtt()`.
    pub fn set_transport_rtt(&mut self, srtt_ms: Option<f64>) {
        self.transport_srtt_ms = srtt_ms;
        if let Some(s) = srtt_ms {
            self.transport_min_rtt_ms = Some(match self.transport_min_rtt_ms {
                Some(m) => m.min(s),
                None => s,
            });
        }
    }

    /// The smoothed RTT used for timing decisions: the transport's if injected,
    /// else the internal sample, else `None` (no estimate yet).
    fn effective_srtt(&self) -> Option<f64> {
        self.transport_srtt_ms
            .or(self.rtt.initialized.then_some(self.rtt.srtt))
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
            seq: self.next_seq,
            old_num: self.assumed().num,
            new_num: crate::instruction::SHUTDOWN_NUM,
            ack_num: self.ack_num,
            throwaway_num: front,
            diff: Vec::new(),
            timestamp: (now & 0xFFFF) as u16,
            timestamp_reply: self.timestamp_reply(now),
        });
        self.next_seq += 1;
    }

    /// Number of retained received states (for tests/observability: must stay
    /// bounded by the configured cap even under hostile input).
    pub fn received_state_count(&self) -> usize {
        self.received_states.len()
    }

    /// Number of retained sent states (for tests/observability: must stay bounded
    /// by [`SspConfig::max_sent_states`]).
    pub fn sent_state_count(&self) -> usize {
        self.sent_states.len()
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
        // to the minimum interval until we have an RTT sample. (Deliberately no
        // congestion backoff: like mosh, we keep pushing the latest state at the
        // frame rate under loss — latest-wins makes a dropped frame harmless, and
        // backing off only adds interactive latency. QUIC's own congestion control
        // already protects the network.)
        let lo = self.cfg.send_interval_min.min(self.cfg.send_interval_max);
        match self.effective_srtt() {
            Some(srtt) => (srtt / 2.0).ceil() as Millis,
            None => self.cfg.send_interval_min,
        }
        .clamp(lo, self.cfg.send_interval_max)
    }

    /// Floor for the RTT-derived RTO (ms), so a tiny RTT can't make us
    /// retransmit absurdly fast.
    const RTO_FLOOR: Millis = 50;

    fn timeout(&self) -> Millis {
        // RTT-derived RTO, clamped to `[floor, cfg.rto]`. `cfg.rto` is the
        // conservative upper bound; the floor keeps us from over-eager resends.
        // If a caller configures `rto` *below* the floor (unusual), honor their
        // smaller bound rather than panicking on an inverted clamp range.
        let floor = Self::RTO_FLOOR.min(self.cfg.rto);
        // Prefer a *base* (minimum) RTT — transport's if injected, else our own
        // seq-guarded min sample. Under burst loss/reorder the smoothed RTT inflates
        // (loss + ack-delay) and would balloon the RTO; the base RTT does not.
        // `factor · base_rtt` gives margin while keeping loss detection fast.
        if let Some(base) = self.transport_min_rtt_ms.or(self.internal_min_rtt_ms) {
            ((base * self.cfg.rto_srtt_factor).ceil() as Millis).clamp(floor, self.cfg.rto)
        } else if self.rtt.initialized {
            // No min sample yet (very first round trips): fall back to Jacobson.
            (self.rtt.rto().ceil() as Millis).clamp(floor, self.cfg.rto)
        } else {
            self.cfg.rto
        }
    }

    /// The assumed receiver state: newest unacked sent state recent enough to
    /// assume delivered. Reverts toward the acked front once the RTO elapses,
    /// which is what triggers retransmission of lost data.
    fn update_assumed_receiver_state(&mut self, now: Millis) {
        self.assumed_receiver_idx = 0;
        let window = self.timeout().saturating_add(self.cfg.ack_delay);
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
        // When `subtract` is a no-op (e.g. the `Screen` direction), the whole
        // routine — a full clone of the acked state plus a `subtract` across every
        // retained sent state — does nothing but burn CPU. Skip it. This runs on
        // every tick, so for the high-cell-count server→client direction it's the
        // single biggest per-frame saving.
        if L::SUBTRACT_IS_NOOP {
            return;
        }
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

        if self.pending_data_ack && self.next_ack_time > now.saturating_add(self.cfg.ack_delay) {
            self.next_ack_time = now.saturating_add(self.cfg.ack_delay);
        }

        let back_ts = self.sent_states.back().expect("never empty").timestamp;
        let has_new_data =
            !self.current_state.equals(&self.sent_states.back().expect("never empty").state);
        let unacked =
            !self.current_state.equals(&self.sent_states.front().expect("never empty").state);
        let assumed_delivered = self.current_state.equals(&self.assumed().state);
        let active = self
            .last_heard
            .saturating_add(self.cfg.active_retry_timeout)
            > now;

        // Once everything we've produced is acked, leave loss-recovery so the next
        // keystroke starts optimistic again (this is what preserves the no-loss
        // median under `FrameRateOnLoss`).
        if !unacked {
            self.in_loss_recovery = false;
        }

        if has_new_data {
            // We have new local data not yet sent.
            if self.mindelay_clock.is_none() {
                self.mindelay_clock = Some(now);
            }
            let mindelay = self
                .mindelay_clock
                .unwrap()
                .saturating_add(self.cfg.send_mindelay);
            self.next_send_time = mindelay.max(back_ts.saturating_add(self.send_interval()));
        } else if !assumed_delivered && active {
            // The assumed-receiver state has reverted below our latest send: a full
            // RTO elapsed with no ack, so that datagram was lost. Confirm loss
            // recovery (gating `FrameRateOnLoss`) and retransmit at frame rate.
            self.in_loss_recovery = true;
            self.next_send_time = back_ts.saturating_add(self.send_interval());
            if let Some(mc) = self.mindelay_clock {
                self.next_send_time = self
                    .next_send_time
                    .max(mc.saturating_add(self.cfg.send_mindelay));
            }
        } else if unacked && active {
            // Sent and still *assumed* delivered, but not yet acked. Normally wait a
            // full RTO before re-poking (prospective-resend re-anchors the diff to
            // the acked front, so the re-poke is a real retransmit). The resend mode
            // can instead retry at the frame interval — always (`FrameRate`) or only
            // after loss is confirmed (`FrameRateOnLoss`), which thins the burst tail
            // while keeping the common no-loss case at one send. See `ResendMode`.
            let fast = match self.cfg.resend_mode {
                ResendMode::FrameRate => true,
                ResendMode::FrameRateOnLoss => self.in_loss_recovery,
                ResendMode::Rto => false,
            };
            self.next_send_time = if fast {
                back_ts.saturating_add(self.send_interval())
            } else {
                back_ts
                    .saturating_add(self.timeout())
                    .saturating_add(self.cfg.ack_delay)
            };
        } else {
            self.next_send_time = NEVER;
        }

        if self.ack_num == u64::MAX {
            // shutdown special-case (reserved)
            self.next_ack_time = back_ts.saturating_add(self.send_interval());
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

    /// Like [`wait_time`](SspCore::wait_time) but **reads the already-computed
    /// timers without recomputing them**. Valid only immediately after
    /// [`tick`](SspCore::tick), which leaves the timers fresh; the driver uses it
    /// to avoid a second full `calculate_timers` (clone + per-state scans) every
    /// loop iteration. `now` may be a fresh clock read for an accurate sleep.
    pub fn pending_wait(&self, now: Millis) -> Option<Millis> {
        let next = if self.shutdown_in_progress {
            self.next_send_time
        } else {
            self.next_ack_time.min(self.next_send_time)
        };
        if next == NEVER {
            None
        } else {
            Some(next.saturating_sub(now))
        }
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
                self.next_send_time = now.saturating_add(self.send_interval());
            }
            return out;
        }

        self.calculate_timers(now);

        if now < self.next_ack_time && now < self.next_send_time {
            return Vec::new();
        }

        let mut diff = self.current_state.diff_from(&self.assumed().state);
        // Prophylactic resend: the assumed-delivered state is only *assumed* — if
        // the datagram that carried it was lost, a diff built on it is unapplyable
        // and the peer drops it, costing a round-trip to recover. Diffing from the
        // *acked* front instead is always applyable; do that when it costs little
        // extra (mosh's `attempt_prospective_resend_optimization`).
        self.attempt_prospective_resend(&mut diff);

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
        // Sending (or the empty-diff timer bookkeeping above) just changed our
        // state, so refresh the timers now — in particular `send_to_receiver` set
        // `next_send_time = NEVER`, and this is what re-derives the retransmit
        // wake. Leaving them fresh lets the driver read them via `pending_wait`
        // instead of recomputing (one fewer `calculate_timers` per loop on the
        // common no-send path). The early `now < …` return above already has
        // fresh timers from the top of `tick`.
        self.calculate_timers(now);
        out
    }

    /// Loss-recovery optimization: consider diffing from the *acked* front state
    /// instead of the merely-assumed-delivered one. The assumed state may have
    /// been lost in flight; a diff anchored on the acked state is always
    /// applyable, so this recovers from a dropped datagram a round-trip sooner.
    /// We only switch when it's nearly free — the front-anchored diff is no bigger
    /// than the proposed one, or at most ~100 bytes bigger and still under 1000.
    /// Mirrors mosh's `attempt_prospective_resend_optimization`.
    fn attempt_prospective_resend(&mut self, proposed: &mut Vec<u8>) {
        // Already anchored on the acked front — nothing to gain.
        if !self.cfg.prospective_resend || self.assumed_receiver_idx == 0 {
            return;
        }
        let resend = {
            let front = &self.sent_states.front().expect("never empty").state;
            self.current_state.diff_from(front)
        };
        let (rlen, plen) = (resend.len(), proposed.len());
        if rlen <= plen || (rlen < 1000 && rlen.saturating_sub(plen) < 100) {
            self.assumed_receiver_idx = 0;
            *proposed = resend;
        }
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
        self.next_ack_time = now.saturating_add(self.cfg.ack_interval);
        self.next_send_time = NEVER;
    }

    fn send_empty_ack(&mut self, now: Millis, out: &mut Vec<Instruction>) {
        let new_num = self.sent_states.back().expect("never empty").num + 1;
        self.add_sent_state(now, new_num);
        self.emit(now, Vec::new(), new_num, out);
        self.next_ack_time = now.saturating_add(self.cfg.ack_interval);
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
            // mirroring mosh's add_sent_state. Clamp the index: `len - 16` matches
            // mosh for the production cap (32), but a `max_sent_states < 16` would
            // otherwise underflow (and in release wrap to a no-op `remove`, leaking
            // the bound). `.max(1)` also guarantees we never evict the front (the
            // acked anchor `emit`/`process_throwaway_until` rely on).
            let remove = self.sent_states.len().saturating_sub(16).max(1);
            self.sent_states.remove(remove);
        }
    }

    fn emit(&mut self, now: Millis, diff: Vec<u8>, new_num: u64, out: &mut Vec<Instruction>) {
        // Fragmentation/MTU-splitting and length-disguising chaff are handled one
        // layer up (the session Driver fragments by transport MTU).
        out.push(Instruction {
            protocol_version: PROTOCOL_VERSION,
            seq: self.next_seq,
            old_num: self.assumed().num,
            new_num,
            ack_num: self.ack_num,
            throwaway_num: self.sent_states.front().expect("never empty").num,
            diff,
            timestamp: (now & 0xFFFF) as u16,
            timestamp_reply: self.timestamp_reply(now),
        });
        self.next_seq += 1;
        self.pending_data_ack = false;
    }

    // ----- Receiving -----

    /// Process one received instruction: update acks, then apply the diff to the
    /// referenced remote state if it is new.
    pub fn recv(&mut self, now: Millis, inst: &Instruction) {
        if inst.protocol_version != PROTOCOL_VERSION {
            return;
        }

        // 0. RTT bookkeeping — *only for in-order packets* (mosh's reorder guard:
        //    `if p.seq < expected_receiver_seq { return p.payload; }`). A reordered
        //    / late datagram carries a stale echoed timestamp; sampling RTT from it
        //    (or echoing its timestamp back) would inflate the estimate and balloon
        //    the RTO — the BRUTAL keyboard-tail bug. Out-of-order packets still flow
        //    through to state application below; they just don't touch timing.
        if inst.seq >= self.expected_recv_seq {
            self.expected_recv_seq = inst.seq.wrapping_add(1);
            // Take a round-trip sample from our echoed timestamp, and remember the
            // peer's timestamp so we can echo it back.
            if let Some(reply) = inst.timestamp_reply {
                let sample = (now as u16).wrapping_sub(reply) as Millis;
                // Guard against absurd samples from clock skew / wraparound.
                if sample < 60_000 {
                    self.rtt.sample(sample);
                    let s = sample as f64;
                    self.internal_min_rtt_ms =
                        Some(self.internal_min_rtt_ms.map_or(s, |m| m.min(s)));
                }
            }
            self.saved_timestamp = Some(inst.timestamp);
            self.saved_timestamp_received_at = now;
        }

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

/// Faithful `Hash` / `Eq` / `Debug` for the bounded model checker
/// (`crate::stateright_model`). Stateright fingerprints every reachable state, so
/// `SspCore` must hash and compare *all* behavior-affecting fields — including the
/// `f64` RTT estimators, which we fold in by their exact bit pattern so two cores
/// compare equal iff they are byte-identical (a sound, non-merging abstraction:
/// distinct cores never collide). `SspConfig` is deliberately excluded — it is
/// constant for the lifetime of a run, so it can't distinguish two reachable
/// states. These live under `cfg(test)` so they impose nothing on normal builds,
/// and inside the defining module so they can read the private fields.
#[cfg(test)]
mod model_check_traits {
    use super::{Rtt, SspCore, Timestamped};
    use crate::state::SyncState;
    use std::fmt;
    use std::hash::{Hash, Hasher};

    fn hash_opt_f64<H: Hasher>(x: &Option<f64>, h: &mut H) {
        match x {
            Some(v) => {
                1u8.hash(h);
                v.to_bits().hash(h);
            }
            None => 0u8.hash(h),
        }
    }

    fn opt_f64_eq(a: &Option<f64>, b: &Option<f64>) -> bool {
        match (a, b) {
            (Some(x), Some(y)) => x.to_bits() == y.to_bits(),
            (None, None) => true,
            _ => false,
        }
    }

    fn ts_eq<S: PartialEq>(a: &Timestamped<S>, b: &Timestamped<S>) -> bool {
        a.timestamp == b.timestamp && a.num == b.num && a.state == b.state
    }

    fn hash_ts<S: Hash, H: Hasher>(t: &Timestamped<S>, h: &mut H) {
        t.timestamp.hash(h);
        t.num.hash(h);
        t.state.hash(h);
    }

    impl<L: SyncState + Hash, R: SyncState + Hash> Hash for SspCore<L, R> {
        fn hash<H: Hasher>(&self, h: &mut H) {
            self.current_state.hash(h);
            self.sent_states.len().hash(h);
            for t in &self.sent_states {
                hash_ts(t, h);
            }
            self.assumed_receiver_idx.hash(h);
            self.next_ack_time.hash(h);
            self.next_send_time.hash(h);
            self.ack_num.hash(h);
            self.pending_data_ack.hash(h);
            self.last_heard.hash(h);
            self.mindelay_clock.hash(h);
            self.next_seq.hash(h);
            self.in_loss_recovery.hash(h);
            hash_opt_f64(&self.transport_srtt_ms, h);
            hash_opt_f64(&self.transport_min_rtt_ms, h);
            self.received_states.len().hash(h);
            for t in &self.received_states {
                hash_ts(t, h);
            }
            self.expected_recv_seq.hash(h);
            let Rtt {
                srtt,
                rttvar,
                initialized,
            } = self.rtt;
            srtt.to_bits().hash(h);
            rttvar.to_bits().hash(h);
            initialized.hash(h);
            hash_opt_f64(&self.internal_min_rtt_ms, h);
            self.saved_timestamp.hash(h);
            self.saved_timestamp_received_at.hash(h);
            self.shutdown_in_progress.hash(h);
            self.shutdown_acked.hash(h);
            self.peer_shutdown.hash(h);
        }
    }

    impl<L: SyncState + PartialEq, R: SyncState + PartialEq> PartialEq for SspCore<L, R> {
        fn eq(&self, o: &Self) -> bool {
            self.current_state == o.current_state
                && self.sent_states.len() == o.sent_states.len()
                && self
                    .sent_states
                    .iter()
                    .zip(&o.sent_states)
                    .all(|(a, b)| ts_eq(a, b))
                && self.assumed_receiver_idx == o.assumed_receiver_idx
                && self.next_ack_time == o.next_ack_time
                && self.next_send_time == o.next_send_time
                && self.ack_num == o.ack_num
                && self.pending_data_ack == o.pending_data_ack
                && self.last_heard == o.last_heard
                && self.mindelay_clock == o.mindelay_clock
                && self.next_seq == o.next_seq
                && self.in_loss_recovery == o.in_loss_recovery
                && opt_f64_eq(&self.transport_srtt_ms, &o.transport_srtt_ms)
                && opt_f64_eq(&self.transport_min_rtt_ms, &o.transport_min_rtt_ms)
                && self.received_states.len() == o.received_states.len()
                && self
                    .received_states
                    .iter()
                    .zip(&o.received_states)
                    .all(|(a, b)| ts_eq(a, b))
                && self.expected_recv_seq == o.expected_recv_seq
                && self.rtt.srtt.to_bits() == o.rtt.srtt.to_bits()
                && self.rtt.rttvar.to_bits() == o.rtt.rttvar.to_bits()
                && self.rtt.initialized == o.rtt.initialized
                && opt_f64_eq(&self.internal_min_rtt_ms, &o.internal_min_rtt_ms)
                && self.saved_timestamp == o.saved_timestamp
                && self.saved_timestamp_received_at == o.saved_timestamp_received_at
                && self.shutdown_in_progress == o.shutdown_in_progress
                && self.shutdown_acked == o.shutdown_acked
                && self.peer_shutdown == o.peer_shutdown
        }
    }

    impl<L: SyncState + PartialEq, R: SyncState + PartialEq> Eq for SspCore<L, R> {}

    impl<L: SyncState + fmt::Debug, R: SyncState + fmt::Debug> fmt::Debug for SspCore<L, R> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let sent: Vec<u64> = self.sent_states.iter().map(|t| t.num).collect();
            let recv: Vec<u64> = self.received_states.iter().map(|t| t.num).collect();
            f.debug_struct("SspCore")
                .field("current", &self.current_state)
                .field("remote", &self.received_states.back().map(|t| &t.state))
                .field("sent_nums", &sent)
                .field("recv_nums", &recv)
                .field("ack_num", &self.ack_num)
                .field("next_seq", &self.next_seq)
                .finish()
        }
    }
}

/// Unit tests for the RTT estimator. The convergence/model-check tests assert
/// *that* the protocol syncs and stays bounded, but deliberately ignore timing —
/// so the latency-critical Jacobson/Karels arithmetic (mosh's keyboard-tail
/// math) was otherwise unpinned. These pin it to exact values; the inputs are
/// chosen so every intermediate is dyadic (exactly representable in `f64`), so
/// any arithmetic change (operator swap, dropped `.abs()`, skipped seeding) moves
/// a result and is caught. (Surfaced by `cargo mutants`.)
#[cfg(test)]
mod rtt_tests {
    use super::Rtt;

    #[test]
    fn first_sample_seeds_srtt_and_rttvar() {
        let mut rtt = Rtt::new();
        rtt.sample(120);
        assert!(rtt.initialized);
        assert_eq!(rtt.srtt, 120.0); // srtt = r
        assert_eq!(rtt.rttvar, 60.0); // rttvar = r / 2
        assert_eq!(rtt.rto(), 120.0 + 4.0 * 60.0); // rto = srtt + 4*rttvar
    }

    #[test]
    fn second_sample_applies_jacobson_ewma() {
        let mut rtt = Rtt::new();
        rtt.sample(100); // seeds srtt=100, rttvar=50
        rtt.sample(200);
        // rttvar = 3/4*50 + 1/4*|100-200| = 37.5 + 25 = 62.5
        // srtt   = 7/8*100 + 1/8*200      = 87.5 + 25 = 112.5
        assert_eq!(rtt.rttvar, 62.5);
        assert_eq!(rtt.srtt, 112.5);
        assert_eq!(rtt.rto(), 112.5 + 4.0 * 62.5);
    }

    #[test]
    fn rttvar_uses_absolute_deviation() {
        // A sample below srtt must move rttvar exactly like one equally above it:
        // pins the `.abs()` (a `srtt - r` -> `srtt + r` mutation breaks this).
        let mut below = Rtt::new();
        below.sample(100);
        below.sample(40); // |100-40| = 60
        let mut above = Rtt::new();
        above.sample(100);
        above.sample(160); // |100-160| = 60
        assert_eq!(below.rttvar, above.rttvar);
        assert_eq!(below.rttvar, 52.5); // 3/4*50 + 1/4*60
        // srtt is directional, though:
        assert_eq!(below.srtt, 92.5); // 7/8*100 + 1/8*40
        assert_eq!(above.srtt, 107.5); // 7/8*100 + 1/8*160
    }
}
