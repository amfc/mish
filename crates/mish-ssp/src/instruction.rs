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
    /// Sender's send time, low 16 bits of milliseconds (for the peer's RTT echo).
    pub timestamp: u16,
    /// Echo of the peer's most-recent `timestamp`, adjusted for hold time, or
    /// `None` if we haven't heard a timestamp yet. The original sender subtracts
    /// this from "now" to get a round-trip sample.
    pub timestamp_reply: Option<u16>,
}

/// Upper bound on a decompressed instruction, to reject a compression bomb (a
/// tiny datagram that inflates to gigabytes) from a hostile/malformed peer. Far
/// above any real instruction (a full repaint of an absurd 2000×2000 screen is a
/// few MB); the downstream `apply_diff` guards the grid size separately.
const MAX_DECOMPRESSED: usize = 64 * 1024 * 1024;

/// Leading flag byte distinguishing a raw vs. deflate-compressed payload.
const RAW: u8 = 0;
const DEFLATED: u8 = 1;

impl Instruction {
    /// Encode to bytes for transmission. The serialized instruction is
    /// deflate-compressed (zlib-rs) when that actually shrinks it — terminal
    /// diffs are highly redundant (repeated SGR/CSI runs), so fewer bytes means
    /// fewer MTU fragments and so less loss exposure on the constrained links
    /// mosh targets. A 1-byte flag selects raw vs. compressed, so tiny or
    /// incompressible payloads never *expand* (beyond that one byte). Compression
    /// is per-instruction and stateless: datagrams are unreliable and unordered,
    /// so a shared cross-message window would desync on the first loss.
    pub fn encode(&self) -> Vec<u8> {
        let raw = bincode::serialize(self).expect("Instruction serialization is infallible");
        // Don't even attempt deflate on tiny payloads — keystroke diffs and empty
        // keepalive acks (the most frequent datagrams by far) can't usefully
        // compress past zlib's own ~6-byte overhead, so deflating them is pure CPU.
        // Larger screen diffs (repeated SGR/CSI runs) still compress and are worth it.
        const DEFLATE_THRESHOLD: usize = 64;
        if raw.len() >= DEFLATE_THRESHOLD {
            let deflated = deflate(&raw);
            if deflated.len() + 1 < raw.len() {
                let mut out = Vec::with_capacity(deflated.len() + 1);
                out.push(DEFLATED);
                out.extend_from_slice(&deflated);
                return out;
            }
        }
        let mut out = Vec::with_capacity(raw.len() + 1);
        out.push(RAW);
        out.extend_from_slice(&raw);
        out
    }

    /// Decode from a received datagram. Returns `None` on malformed input
    /// (treated as a dropped datagram) — including a compression bomb, which is
    /// rejected by [`MAX_DECOMPRESSED`] rather than allocated.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let (&flag, payload) = bytes.split_first()?;
        match flag {
            RAW => bincode::deserialize(payload).ok(),
            DEFLATED => {
                let raw = inflate(payload, MAX_DECOMPRESSED)?;
                bincode::deserialize(&raw).ok()
            }
            _ => None,
        }
    }

    /// Whether this instruction carries an actual state change (vs. a pure ack).
    pub fn has_diff(&self) -> bool {
        !self.diff.is_empty()
    }
}

/// Raw-deflate compress (no zlib header/checksum — fewest bytes for small
/// messages). Backed by zlib-rs via flate2.
fn deflate(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut enc = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(data)
        .and_then(|_| enc.finish())
        .expect("in-memory deflate is infallible")
}

/// Inflate a raw-deflate stream, refusing to produce more than `max` bytes (a
/// compression-bomb guard) and returning `None` on any malformed input.
fn inflate(data: &[u8], max: usize) -> Option<Vec<u8>> {
    use std::io::Read;
    let dec = flate2::read::DeflateDecoder::new(data);
    let mut out = Vec::new();
    // Read at most max+1 bytes: if we hit max+1 the stream is over-budget (bomb),
    // otherwise we got the complete, in-bounds output.
    dec.take(max as u64 + 1).read_to_end(&mut out).ok()?;
    if out.len() > max {
        return None;
    }
    Some(out)
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
            timestamp: 1234,
            timestamp_reply: Some(1000),
        };
        let bytes = inst.encode();
        assert_eq!(Instruction::decode(&bytes), Some(inst));
    }

    #[test]
    fn decode_garbage_is_none_or_err() {
        // Truncated / nonsense input must never panic.
        let _ = Instruction::decode(&[]);
        let _ = Instruction::decode(&[0xff, 0x00, 0x01]);
        // Flag byte present but payload garbage (both raw and deflated paths).
        let _ = Instruction::decode(&[RAW, 0x01, 0x02]);
        let _ = Instruction::decode(&[DEFLATED, 0x01, 0x02, 0x03]);
    }

    fn inst_with_diff(diff: Vec<u8>) -> Instruction {
        Instruction {
            protocol_version: PROTOCOL_VERSION,
            old_num: 1,
            new_num: 2,
            ack_num: 0,
            throwaway_num: 0,
            diff,
            timestamp: 0,
            timestamp_reply: None,
        }
    }

    #[test]
    fn redundant_diff_is_compressed() {
        // A realistic, highly-redundant terminal diff (repeated SGR runs).
        let diff = b"\x1b[0m\x1b[1;32mhello \x1b[0m".repeat(200);
        let inst = inst_with_diff(diff.clone());
        let encoded = inst.encode();
        assert_eq!(encoded[0], DEFLATED, "redundant diff should compress");
        assert!(
            encoded.len() < diff.len(),
            "compressed ({}) should beat the raw diff ({})",
            encoded.len(),
            diff.len()
        );
        assert_eq!(Instruction::decode(&encoded), Some(inst), "round-trips");
    }

    #[test]
    fn never_expands_beyond_flag_byte() {
        // Across an empty ack and a varied diff, the encoding must never exceed
        // the raw bincode length by more than the single flag byte (the RAW
        // branch is the fallback whenever deflate wouldn't help), and must always
        // round-trip.
        for diff in [
            Vec::new(),
            (0..64u16)
                .map(|i| (i.wrapping_mul(97) ^ 0x5a) as u8)
                .collect(),
        ] {
            let inst = inst_with_diff(diff);
            let enc = inst.encode();
            let raw_len = bincode::serialize(&inst).unwrap().len();
            assert!(
                enc.len() <= raw_len + 1,
                "encoding must not expand the payload"
            );
            assert_eq!(Instruction::decode(&enc), Some(inst));
        }
    }

    /// Tiny payloads (keystrokes, empty acks) skip deflate entirely — they encode
    /// RAW and still round-trip. Guards the `DEFLATE_THRESHOLD` fast path.
    #[test]
    fn tiny_payloads_skip_deflate() {
        for diff in [Vec::new(), b"a".to_vec(), b"echo hi\r".to_vec()] {
            let inst = inst_with_diff(diff);
            let enc = inst.encode();
            assert_eq!(enc[0], RAW, "tiny payload must not be deflated");
            assert_eq!(Instruction::decode(&enc), Some(inst), "round-trips");
        }
    }

    /// Directly exercise the RAW-selection branch via the helper: random bytes
    /// don't shrink under deflate.
    #[test]
    fn deflate_does_not_shrink_random() {
        let random: Vec<u8> = (0..256u32)
            .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
            .collect();
        assert!(
            deflate(&random).len() >= random.len(),
            "incompressible data should not shrink"
        );
    }

    #[test]
    fn inflate_rejects_a_bomb() {
        // 256 KiB of zeros deflates to a few hundred bytes; inflating with a tiny
        // budget must refuse rather than allocate the full output.
        let bomb = deflate(&vec![0u8; 256 * 1024]);
        assert!(bomb.len() < 1024, "zeros compress tiny");
        assert_eq!(inflate(&bomb, 4096), None, "over-budget output is rejected");
        // Within budget, it inflates correctly.
        assert_eq!(inflate(&bomb, 512 * 1024).unwrap().len(), 256 * 1024);
    }
}
