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

use std::collections::HashMap;

use bytes::Bytes;

/// Bytes of per-fragment header: `id: u32 | count: u16 | index: u16` (LE).
pub const FRAGMENT_HEADER: usize = 8;

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
}

/// Reassembles fragments back into whole instruction payloads.
pub struct Defragmenter {
    in_progress: HashMap<u32, Partial>,
    /// Cap on concurrently-reassembling instructions; stale ones are evicted.
    max_in_progress: usize,
}

impl Default for Defragmenter {
    fn default() -> Self {
        Self {
            in_progress: HashMap::new(),
            max_in_progress: 64,
        }
    }
}

impl Defragmenter {
    pub fn new() -> Self {
        Self::default()
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
            self.in_progress.remove(&id);
            return Some(body.to_vec());
        }

        let entry = self.in_progress.entry(id).or_insert_with(|| Partial {
            count,
            received: 0,
            chunks: vec![None; count as usize],
        });
        // Guard against inconsistent `count` across fragments of one id.
        if entry.count != count {
            return None;
        }
        let slot = &mut entry.chunks[index as usize];
        if slot.is_none() {
            *slot = Some(body.to_vec());
            entry.received += 1;
        }

        if entry.received == entry.count {
            let entry = self.in_progress.remove(&id).expect("just inserted");
            let mut payload = Vec::new();
            for chunk in entry.chunks {
                payload.extend_from_slice(&chunk.expect("all chunks present"));
            }
            return Some(payload);
        }

        // Bound memory: if too many half-finished instructions pile up, drop the
        // oldest (lowest id) — SSP will resend whatever we discard.
        if self.in_progress.len() > self.max_in_progress {
            if let Some(&oldest) = self.in_progress.keys().min() {
                self.in_progress.remove(&oldest);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
