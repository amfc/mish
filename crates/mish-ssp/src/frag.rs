//! Instruction fragmentation and reassembly.
//!
//! SSP instructions (especially a full-screen diff) routinely exceed a single
//! datagram's MTU, but a [`crate::transport::Transport`] only moves whole
//! datagrams. This module splits an encoded instruction across several datagrams
//! and reassembles them — mosh's `Fragmenter` / `FragmentAssembly`.
//!
//! Reliability still comes from SSP, not from here: if any fragment of an
//! instruction is lost, the instruction is simply never reassembled, and the
//! sender re-diffs and retransmits a fresh one. Incomplete reassembly buffers
//! are therefore disposable and bounded — stale ones are evicted.

use std::collections::hash_map::Entry;
use std::collections::HashMap;

use bytes::Bytes;

/// Bytes of per-fragment header: `id: u32 | count: u16 | index: u16` (LE).
pub const FRAGMENT_HEADER: usize = 8;

/// Cap on total bytes held across all in-progress reassemblies. `count` is
/// peer-controlled, so without this a hostile peer could pin large memory by
/// opening many never-completed reassemblies; the oldest are dropped to stay
/// under it (SSP resends). Generous next to a real in-flight instruction.
const MAX_REASSEMBLY_BYTES: usize = 8 * 1024 * 1024;

/// Splits encoded instructions into datagram-sized fragments.
#[derive(Default)]
pub struct Fragmenter {
    next_id: u32,
}

impl Fragmenter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Split `payload` into fragments each no larger than `max_datagram`.
    ///
    /// Every fragment carries a header identifying its instruction and position.
    /// A payload that fits in one datagram becomes a single fragment.
    pub fn fragment(&mut self, payload: &[u8], max_datagram: usize) -> Vec<Bytes> {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);

        // Usable bytes per datagram. Guard against absurdly small MTUs.
        let chunk = max_datagram.saturating_sub(FRAGMENT_HEADER).max(1);
        let count = payload.len().div_ceil(chunk).max(1);
        // `count` must fit a u16; with realistic MTUs this is never exceeded, but
        // clamp defensively (the instruction would then be undersent and re-diffed).
        let count = count.min(u16::MAX as usize);

        let mut out = Vec::with_capacity(count);
        for index in 0..count {
            let start = index * chunk;
            let end = (start + chunk).min(payload.len());
            let slice = &payload[start..end];
            let mut buf = Vec::with_capacity(FRAGMENT_HEADER + slice.len());
            buf.extend_from_slice(&id.to_le_bytes());
            buf.extend_from_slice(&(count as u16).to_le_bytes());
            buf.extend_from_slice(&(index as u16).to_le_bytes());
            buf.extend_from_slice(slice);
            out.push(Bytes::from(buf));
        }
        out
    }
}

struct Partial {
    count: u16,
    received: u16,
    chunks: Vec<Option<Vec<u8>>>,
    /// Running byte cost of this reassembly — the pre-allocated chunk-slot vector
    /// plus the buffered fragment bodies so far. Summed into
    /// [`Defragmenter::buffered`] so the memory cap is an O(1) check rather than a
    /// full rescan of every reassembly on each push.
    bytes: usize,
}

/// Reassembles fragments back into whole instruction payloads.
pub struct Defragmenter {
    in_progress: HashMap<u32, Partial>,
    /// Cap on concurrently-reassembling instructions; stale ones are evicted.
    max_in_progress: usize,
    /// Running sum of every [`Partial::bytes`], kept in lockstep with insertions,
    /// slot fills, and removals so [`buffered_bytes`](Self::buffered_bytes) is
    /// O(1) on the per-datagram recv hot path.
    buffered: usize,
}

impl Default for Defragmenter {
    fn default() -> Self {
        Self {
            in_progress: HashMap::new(),
            max_in_progress: 64,
            buffered: 0,
        }
    }
}

impl Defragmenter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Test/fuzz support: an estimate of the bytes currently held across all
    /// in-progress reassemblies — the pre-allocated chunk-slot vectors (sized from
    /// the peer-supplied `count`) plus the buffered fragment bodies. The
    /// `frag_memory_bounds` fuzz target asserts a hostile peer can't drive this
    /// unbounded. Maintained incrementally (see [`Defragmenter::buffered`]), so
    /// this is O(1).
    #[doc(hidden)]
    pub fn buffered_bytes(&self) -> usize {
        self.buffered
    }

    /// The byte cost of a chunk-slot table for `count` fragments (the fixed
    /// overhead charged when a reassembly is first opened, before any bodies land).
    fn slot_table_bytes(count: u16) -> usize {
        count as usize * std::mem::size_of::<Option<Vec<u8>>>()
    }

    /// Feed one received datagram. Returns the full payload once the last
    /// missing fragment of some instruction arrives; otherwise `None`.
    /// Malformed datagrams are ignored (treated as drops).
    pub fn push(&mut self, datagram: &[u8]) -> Option<Vec<u8>> {
        if datagram.len() < FRAGMENT_HEADER {
            return None;
        }
        let id = u32::from_le_bytes([datagram[0], datagram[1], datagram[2], datagram[3]]);
        let count = u16::from_le_bytes([datagram[4], datagram[5]]);
        let index = u16::from_le_bytes([datagram[6], datagram[7]]);
        let body = &datagram[FRAGMENT_HEADER..];

        if count == 0 || index >= count {
            return None;
        }

        // Fast path: single-fragment instruction.
        if count == 1 {
            if let Some(removed) = self.in_progress.remove(&id) {
                self.buffered -= removed.bytes;
            }
            return Some(body.to_vec());
        }

        let entry = match self.in_progress.entry(id) {
            Entry::Occupied(e) => e.into_mut(),
            Entry::Vacant(v) => {
                let overhead = Self::slot_table_bytes(count);
                self.buffered += overhead;
                v.insert(Partial {
                    count,
                    received: 0,
                    chunks: vec![None; count as usize],
                    bytes: overhead,
                })
            }
        };
        // Guard against inconsistent `count` across fragments of one id.
        if entry.count != count {
            return None;
        }
        let slot = &mut entry.chunks[index as usize];
        if slot.is_none() {
            *slot = Some(body.to_vec());
            entry.received += 1;
            entry.bytes += body.len();
            self.buffered += body.len();
        }

        if entry.received == entry.count {
            let entry = self.in_progress.remove(&id).expect("just inserted");
            self.buffered -= entry.bytes;
            let mut payload = Vec::new();
            for chunk in entry.chunks {
                payload.extend_from_slice(&chunk.expect("all chunks present"));
            }
            return Some(payload);
        }

        // Bound memory: drop the oldest (lowest id) half-finished instructions
        // until we're under *both* caps — SSP resends whatever we discard. The
        // byte cap matters because `count` is peer-controlled (up to 65535), so a
        // hostile peer could open many ids each pre-allocating a huge chunk table;
        // capping only the entry count leaves total memory unbounded.
        while self.in_progress.len() > self.max_in_progress || self.buffered > MAX_REASSEMBLY_BYTES
        {
            let Some(&oldest) = self.in_progress.keys().min() else {
                break;
            };
            if let Some(removed) = self.in_progress.remove(&oldest) {
                self.buffered -= removed.bytes;
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Security regression (`frag_memory_bounds` target): a hostile peer opens many
    /// reassemblies, each declaring the max fragment `count` (so a huge chunk table
    /// is pre-allocated) with a single tiny body, and never completes them. Total
    /// buffered memory must stay bounded, not grow to ~count×entries.
    ///
    /// Skipped under Miri: it allocates ~500×65535 chunk-table slots, which Miri's
    /// interpreter is far too slow to churn through. This is a memory-*bound*
    /// property, not a memory-safety one — the `frag_memory_bounds` fuzz target
    /// covers it, and the smaller frag tests give Miri its UB coverage here.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn reassembly_memory_is_bounded_against_hostile_count() {
        let mut d = Defragmenter::new();
        for id in 0..500u32 {
            let mut dg = Vec::new();
            dg.extend_from_slice(&id.to_le_bytes()); // id
            dg.extend_from_slice(&u16::MAX.to_le_bytes()); // count = 65535
            dg.extend_from_slice(&0u16.to_le_bytes()); // index 0
            dg.push(0xab); // 1-byte body
            d.push(&dg);
        }
        assert!(
            d.buffered_bytes() <= 16 * 1024 * 1024,
            "reassembler held {} bytes against a hostile peer",
            d.buffered_bytes()
        );
    }

    #[test]
    fn single_fragment_roundtrip() {
        let mut f = Fragmenter::new();
        let mut d = Defragmenter::new();
        let payload = b"small payload".to_vec();
        let frags = f.fragment(&payload, usize::MAX);
        assert_eq!(frags.len(), 1);
        assert_eq!(d.push(&frags[0]), Some(payload));
    }

    #[test]
    fn multi_fragment_roundtrip() {
        let mut f = Fragmenter::new();
        let mut d = Defragmenter::new();
        let payload: Vec<u8> = (0..5000u32).map(|i| i as u8).collect();
        let frags = f.fragment(&payload, 1200);
        assert!(frags.len() >= 4, "should split into several fragments");
        let mut result = None;
        for frag in &frags {
            if let Some(p) = d.push(frag) {
                result = Some(p);
            }
        }
        assert_eq!(result, Some(payload));
    }

    #[test]
    fn out_of_order_reassembly() {
        let mut f = Fragmenter::new();
        let mut d = Defragmenter::new();
        let payload: Vec<u8> = (0..3000u32).map(|i| (i * 7) as u8).collect();
        let mut frags = f.fragment(&payload, 1000);
        frags.reverse();
        let mut result = None;
        for frag in &frags {
            if let Some(p) = d.push(frag) {
                result = Some(p);
            }
        }
        assert_eq!(result, Some(payload));
    }

    #[test]
    fn lost_fragment_yields_nothing() {
        let mut f = Fragmenter::new();
        let mut d = Defragmenter::new();
        let payload: Vec<u8> = (0..3000u32).map(|i| i as u8).collect();
        let frags = f.fragment(&payload, 1000);
        // Drop the middle fragment; reassembly must never complete.
        for (i, frag) in frags.iter().enumerate() {
            if i == frags.len() / 2 {
                continue;
            }
            assert_eq!(d.push(frag), None);
        }
    }
}
