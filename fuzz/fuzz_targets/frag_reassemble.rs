//! Fuzz the fragment reassembler: arbitrary datagram chunks fed to a
//! `Defragmenter` must never panic or grow memory without bound (overlapping,
//! duplicate, out-of-order, huge-offset, and truncated fragment headers are a
//! classic bug farm). Also checks the honest round-trip: a payload fragmented by
//! `Fragmenter` and pushed back in reassembles to the original.
//!
//! Run with: `cargo +nightly fuzz run frag_reassemble`.
#![no_main]
use libfuzzer_sys::fuzz_target;
use mish_ssp::frag::{Defragmenter, Fragmenter};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    // 1. Hostile path: treat `data` as a sequence of length-prefixed "datagrams"
    //    and push each chunk straight at the defragmenter. Must never panic.
    let mut defrag = Defragmenter::new();
    let mut i = 0usize;
    while i < data.len() {
        let len = data[i] as usize; // 0..=255 chunk length
        i += 1;
        let end = (i + len).min(data.len());
        let _ = defrag.push(&data[i..end]);
        i = end;
    }

    // 2. Honest round-trip: fragment the whole input at a small MTU and feed the
    //    pieces (in order) back; the last piece must yield the original payload.
    let mtu = 8 + (data[0] as usize % 200); // vary the MTU, keep it > header
    let mut frag = Fragmenter::new();
    let pieces = frag.fragment(data, mtu);
    let mut defrag2 = Defragmenter::new();
    let mut out = None;
    for p in &pieces {
        if let Some(payload) = defrag2.push(p) {
            out = Some(payload);
        }
    }
    assert_eq!(out.as_deref(), Some(data), "fragment/reassemble round-trip");
});
