//! The [`SyncState`] trait: anything the protocol can synchronize.
//!
//! In mosh the two synchronized states are `Complete` (the terminal screen,
//! server→client) and `UserStream` (queued keystrokes, client→server). The SSP
//! core is generic over the state type; it only needs to (a) compute a diff that
//! transforms one state into another, (b) apply such a diff, and (c) compare
//! states for equality. `subtract` lets a state garbage-collect information the
//! receiver is already known to have, so states don't grow without bound.

/// A state that can be synchronized by computing and applying diffs.
///
/// Contract (the protocol relies on these and the property tests enforce them):
///
/// * **Round-trip:** for any `a`, `b`: clone `b`, then
///   `clone_of_b.apply_diff(&a.diff_from(&b))` yields a state equal to `a`.
/// * **Idempotency:** applying the same diff twice equals applying it once.
/// * **Empty diff:** `a.diff_from(&a)` may be anything, but if `a.equals(&b)` then
///   sending no diff is valid; the core treats an empty diff as "no change".
pub trait SyncState: Clone {
    /// The initial, empty state both peers agree on at connection start (num 0).
    fn new_initial() -> Self;

    /// Produce a diff that, applied to a clone of `prev`, reconstructs `self`.
    ///
    /// Returning an empty `Vec` signals "no change from `prev`".
    fn diff_from(&self, prev: &Self) -> Vec<u8>;

    /// Apply a diff produced by [`SyncState::diff_from`] to `self` in place.
    fn apply_diff(&mut self, diff: &[u8]);

    /// Discard from `self` any information that `prev` is already known to hold.
    ///
    /// Used to bound memory (mosh calls this "rationalization"). The default is a
    /// no-op, which is always correct but may retain more than necessary.
    fn subtract(&mut self, _prev: &Self) {}

    /// Protocol-level equality. Must be reflexive/symmetric/transitive and
    /// consistent with `diff_from` (equal states diff to an empty change).
    fn equals(&self, other: &Self) -> bool;
}
