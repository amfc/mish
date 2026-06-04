//! The wire-level [`Instruction`]: one SSP message.
//!
//! Mirrors mosh's `TransportBuffers.Instruction` (protobuf). Every datagram
//! carries exactly one instruction describing a state transition the receiver
//! should apply, plus piggy-backed acknowledgement bookkeeping.
//!
//! Mosh additionally fragments instructions larger than the MTU and adds random
//! "chaff" to disguise length; those concerns are deferred (see `FRAGMENTATION`
//! note below) until the QUIC datagram transport lands.

use serde::{Deserialize, Serialize};

/// Current protocol version. Bumped on incompatible wire changes.
pub const PROTOCOL_VERSION: u32 = 1;

/// Sentinel state number used by mosh to mean "shutdown" (`uint64(-1)`).
/// Reserved here; the shutdown handshake is not yet implemented.
pub const SHUTDOWN_NUM: u64 = u64::MAX;

/// A single SSP message.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Instruction {
    /// Protocol version of the sender.
    pub protocol_version: u32,
    /// State number this diff is computed *from* (the assumed receiver state).
    /// The receiver must already hold a state with this number, or it drops the
    /// instruction — this is how idempotency and replay-safety are enforced.
    pub old_num: u64,
    /// State number this diff produces.
    pub new_num: u64,
    /// Highest state number the sender has received from the peer (the ack).
    pub ack_num: u64,
    /// The earliest state number the sender still needs the receiver to keep;
    /// the receiver may garbage-collect anything older.
    pub throwaway_num: u64,
    /// The diff, as produced by [`crate::state::SyncState::diff_from`]. Empty
    /// means "no state change" (a pure ack / keepalive).
    pub diff: Vec<u8>,
}

impl Instruction {
    /// Encode to bytes for transmission in a single datagram.
    pub fn encode(&self) -> Vec<u8> {
        // bincode is deterministic and compact enough for milestone 1; the wire
        // format is an internal detail and may change before 1.0.
        bincode::serialize(self).expect("Instruction serialization is infallible")
    }

    /// Decode from a received datagram. Returns `None` on malformed input
    /// (which the protocol treats as a dropped datagram).
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        bincode::deserialize(bytes).ok()
    }

    /// Whether this instruction carries an actual state change (vs. a pure ack).
    pub fn has_diff(&self) -> bool {
        !self.diff.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip() {
        let inst = Instruction {
            protocol_version: PROTOCOL_VERSION,
            old_num: 3,
            new_num: 4,
            ack_num: 7,
            throwaway_num: 2,
            diff: b"some diff bytes".to_vec(),
        };
        let bytes = inst.encode();
        assert_eq!(Instruction::decode(&bytes), Some(inst));
    }

    #[test]
    fn decode_garbage_is_none_or_err() {
        // Truncated / nonsense input must never panic.
        let _ = Instruction::decode(&[]);
        let _ = Instruction::decode(&[0xff, 0x00, 0x01]);
    }
}
