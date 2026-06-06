//! Security target — **resource bounds** on the fragment reassembler. A hostile
//! authenticated peer streams datagrams; QUIC AEAD proves they're authentic, not
//! benign. Each fragment carries a peer-chosen `count` (up to 65535) and the
//! reassembler buffers fragment bodies until an instruction completes. The
//! documented guard caps the *number* of concurrent reassemblies; this target
//! asserts the *total buffered bytes* also stays bounded, so a peer can't make
//! the receiver hold arbitrary memory by opening many large, never-completed
//! reassemblies.
//!
//! Run with: `cargo +nightly fuzz run frag_memory_bounds`.
#![no_main]
use libfuzzer_sys::fuzz_target;
use mish_ssp::frag::Defragmenter;

/// Generous ceiling on what the reassembler may hold at once. A real in-flight
/// instruction is well under this; the point is that it is *bounded* regardless
/// of how a peer sets `count` or how many ids it opens.
const BUDGET: usize = 16 * 1024 * 1024;

fuzz_target!(|data: &[u8]| {
    let mut defrag = Defragmenter::new();

    // Interpret the input as a sequence of datagrams: a 2-byte length prefix then
    // that many bytes, repeated — so the fuzzer controls each datagram's size and
    // content (including the fragment header: id, count, index).
    let mut i = 0;
    while i + 2 <= data.len() {
        let len = u16::from_le_bytes([data[i], data[i + 1]]) as usize;
        i += 2;
        let end = (i + len).min(data.len());
        let datagram = &data[i..end];
        i = end;

        let _ = defrag.push(datagram);

        assert!(
            defrag.buffered_bytes() <= BUDGET,
            "reassembler buffered {} bytes (> {} budget) — hostile peer can exhaust memory",
            defrag.buffered_bytes(),
            BUDGET
        );
    }
});
