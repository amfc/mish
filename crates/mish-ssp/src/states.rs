//! Concrete [`SyncState`] implementations.
//!
//! For now this is just [`BytesState`], a simple byte-buffer state used by tests
//! and examples. The real terminal states (`Complete` / `UserStream`) will live
//! in the `mish-terminal` crate once the alacritty-terminal layer lands.

use crate::state::SyncState;

/// A synchronized opaque byte buffer.
///
/// The diff format is a real (if simple) prefix diff: `[common_prefix_len: u32
/// LE][tail bytes]`. Applying it truncates the reference to the common prefix
/// then appends the tail. This exercises the `diff_from(prev)` path rather than
/// shipping the whole state every time.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct BytesState(pub Vec<u8>);

impl BytesState {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

fn common_prefix_len(a: &[u8], b: &[u8]) -> usize {
    a.iter().zip(b.iter()).take_while(|(x, y)| x == y).count()
}

impl SyncState for BytesState {
    fn new_initial() -> Self {
        Self(Vec::new())
    }

    fn diff_from(&self, prev: &Self) -> Vec<u8> {
        if self.0 == prev.0 {
            return Vec::new();
        }
        let common = common_prefix_len(&self.0, &prev.0);
        let mut out = Vec::with_capacity(4 + self.0.len() - common);
        out.extend_from_slice(&(common as u32).to_le_bytes());
        out.extend_from_slice(&self.0[common..]);
        out
    }

    fn apply_diff(&mut self, diff: &[u8]) {
        if diff.is_empty() {
            return;
        }
        // Untrusted input: a malformed (too-short) diff is ignored, not panicked.
        if diff.len() < 4 {
            return;
        }
        let common = u32::from_le_bytes([diff[0], diff[1], diff[2], diff[3]]) as usize;
        let tail = &diff[4..];
        // Clamp the truncation point so a hostile `common` can't misbehave.
        let common = common.min(self.0.len());
        self.0.truncate(common);
        self.0.extend_from_slice(tail);
    }

    fn equals(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(from: &[u8], to: &[u8]) {
        let prev = BytesState::new(from);
        let target = BytesState::new(to);
        let diff = target.diff_from(&prev);
        let mut applied = prev.clone();
        applied.apply_diff(&diff);
        assert_eq!(applied, target, "round-trip {from:?} -> {to:?}");
        // idempotent
        applied.apply_diff(&diff);
        assert_eq!(applied, target, "idempotent {from:?} -> {to:?}");
    }

    #[test]
    fn diff_roundtrips() {
        roundtrip(b"", b"hello");
        roundtrip(b"hello", b"hello world");
        roundtrip(b"hello world", b"hello");
        roundtrip(b"abc", b"abd");
        roundtrip(b"same", b"same");
        roundtrip(b"prefix-changes", b"completely different");
    }

    #[test]
    fn diff_compresses_shared_prefix() {
        // The round-trip tests pass even if the diff just reships the whole state,
        // so they don't pin `common_prefix_len` (a `-> 0` mutation degrades this
        // to a full-replacement diff unnoticed). Assert the diff carries only the
        // 4-byte prefix-length header + the differing tail, not the long prefix.
        let prev = BytesState::new(vec![7u8; 1000]);
        let mut bytes = vec![7u8; 1000];
        bytes.extend_from_slice(b"tail");
        let next = BytesState::new(bytes);
        let diff = next.diff_from(&prev);
        assert_eq!(diff.len(), 4 + b"tail".len(), "diff must not reship the prefix");
        let mut applied = prev.clone();
        applied.apply_diff(&diff);
        assert_eq!(applied, next);
    }
}
