//! The `UserStream` state: the client's queued input (keystrokes + resizes),
//! synchronized client → server.
//!
//! Like mosh's `UserStream`, this is an append-only log of [`UserEvent`]s. The
//! diff from an earlier version is simply the suffix of events the receiver
//! hasn't seen yet, keyed by an absolute index so the log can be trimmed
//! (via [`SyncState::subtract`]) once the server has acknowledged events without
//! breaking diffing. Pure data — no I/O, no terminal dependency.

use std::collections::VecDeque;

use mish_ssp::state::SyncState;
use serde::{Deserialize, Serialize};

/// Upper bound on the number of event bodies the *receiver* (server) retains in
/// a single reconstructed `UserStream`.
///
/// The receiver only ever *reads* the suffix it has not yet processed (via
/// [`UserStream::events_since`]); older event bodies are dead weight kept solely
/// because [`SyncState::apply_diff`] appends. Without a bound the deque grows
/// without limit — both as a slow leak on any long-lived session (the receiver,
/// unlike the sender, never trims as the peer keeps typing) and as a post-auth
/// memory-amplification DoS: a peer can stream input while pinning
/// `throwaway_num` so the SSP core can't GC the snapshots that hold these
/// streams (see `core::SspCore::recv`). We trim from the *front*, which preserves
/// [`UserStream::total`] and therefore both the idempotent `abs >= total`
/// accounting and the `old_num -> new_num` diff chain. The cap is far above any
/// legitimate unprocessed backlog — the server drains the whole newest stream on
/// every datagram through the latest-wins `watch` channel — so a real session
/// never drops unread input; only a flooding/stalled peer ever reaches it, and
/// it only harms its own connection. Mirrors the byte caps in `frag.rs` and the
/// `max_received_states` quench.
const MAX_RETAINED_EVENTS: usize = 1 << 16;

/// One unit of user input.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum UserEvent {
    /// Raw bytes from the terminal (a keystroke or paste chunk).
    Keystroke(Vec<u8>),
    /// The client's terminal was resized.
    Resize { cols: u16, rows: u16 },
}

/// An append-only stream of user events with a trimmable front.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct UserStream {
    /// Absolute index of `events[0]` — i.e. how many events were trimmed.
    base: u64,
    events: VecDeque<UserEvent>,
}

impl UserStream {
    pub fn new() -> Self {
        Self {
            base: 0,
            events: VecDeque::new(),
        }
    }

    /// Total number of events ever appended (including trimmed ones). This is
    /// the stable cursor used for diffing and for the server to track progress.
    pub fn total(&self) -> u64 {
        self.base + self.events.len() as u64
    }

    pub fn push(&mut self, event: UserEvent) {
        self.events.push_back(event);
    }

    pub fn push_keystroke(&mut self, bytes: impl Into<Vec<u8>>) {
        self.push(UserEvent::Keystroke(bytes.into()));
    }

    pub fn push_resize(&mut self, cols: u16, rows: u16) {
        self.push(UserEvent::Resize { cols, rows });
    }

    /// Number of event bodies currently retained (after front-trimming). Bounded
    /// by `MAX_RETAINED_EVENTS`; useful for diagnostics and the retention test.
    pub fn retained_len(&self) -> usize {
        self.events.len()
    }

    /// Iterate events whose absolute index is `>= from`. The server calls this
    /// with the count it has already processed to get only the new events.
    pub fn events_since(&self, from: u64) -> impl Iterator<Item = &UserEvent> {
        let skip = from.saturating_sub(self.base) as usize;
        self.events.iter().skip(skip)
    }
}

impl Default for UserStream {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Serialize, Deserialize)]
struct StreamDiff {
    /// Absolute index of the first event in `suffix`.
    start: u64,
    suffix: Vec<UserEvent>,
}

impl SyncState for UserStream {
    fn new_initial() -> Self {
        Self::new()
    }

    fn diff_from(&self, prev: &Self) -> Vec<u8> {
        let from = prev.total();
        if from >= self.total() {
            return Vec::new(); // receiver already has everything
        }
        // `prev` must be an ancestor, so its total is within our retained range.
        debug_assert!(from >= self.base, "diffing against a trimmed-away ancestor");
        let start_idx = from.saturating_sub(self.base) as usize;
        let suffix: Vec<UserEvent> = self.events.iter().skip(start_idx).cloned().collect();
        bincode::serialize(&StreamDiff {
            start: from,
            suffix,
        })
        .expect("user stream diff serialization is infallible")
    }

    fn apply_diff(&mut self, diff: &[u8]) {
        if diff.is_empty() {
            return;
        }
        let diff: StreamDiff = match bincode::deserialize(diff) {
            Ok(d) => d,
            Err(_) => return,
        };
        let total = self.total();
        for (i, ev) in diff.suffix.into_iter().enumerate() {
            // Idempotent: only append events we don't already have.
            // `start` comes off the wire untrusted; saturate so a hostile
            // `start` near u64::MAX can't overflow the index (stays huge ⇒ the
            // `abs >= total` guard still holds and the event is appended).
            let abs = diff.start.saturating_add(i as u64);
            if abs >= total {
                self.events.push_back(ev);
            }
        }
        // Bound retained event bodies so a flooding/stalled peer can't grow this
        // stream without limit. Trimming the front advances `base` and leaves
        // `total()` unchanged, so the idempotent `abs >= total` guard above and
        // the SSP diff chain are unaffected — see `MAX_RETAINED_EVENTS`.
        while self.events.len() > MAX_RETAINED_EVENTS {
            self.events.pop_front();
            self.base += 1;
        }
    }

    // `subtract` trims acknowledged events, so rationalization is NOT a no-op here.
    const SUBTRACT_IS_NOOP: bool = false;

    fn subtract(&mut self, prev: &Self) {
        // Drop events the receiver (`prev`) is known to already hold.
        let drop_to = prev.total();
        while self.base < drop_to && !self.events.is_empty() {
            self.events.pop_front();
            self.base += 1;
        }
    }

    fn equals(&self, other: &Self) -> bool {
        // Logical equality: same total and same retained tail. Within one
        // sender all states are subtracted against the same base, so this is
        // consistent.
        self.total() == other.total() && self.events == other.events
    }
}
