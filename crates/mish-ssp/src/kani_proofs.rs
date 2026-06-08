//! Kani bounded-proof harnesses for the fragment reassembler.
//!
//! These are the *proof* companion to the `frag_reassemble` / `frag_memory_bounds`
//! libFuzzer targets. Where the fuzzer *samples* inputs looking for a crash, Kani
//! symbolically explores **every** input within an explicit bound and proves the
//! absence of panics, integer overflow/underflow, and out-of-bounds indexing — a
//! complete result over that bounded domain rather than a probabilistic one.
//!
//! Why `frag` and not `instruction::decode`: this module is pure, dependency-free
//! index/arithmetic code (header parse, bounds checks, a `HashMap` of small
//! reassembly buffers) — the kind of logic Kani discharges cleanly. `decode`
//! immediately calls into `bincode` and zlib `inflate` (flate2), whose internal
//! loops and attacker-length allocations are opaque/intractable to the model
//! checker; those paths stay the fuzzers' job. See the note at the bottom.
//!
//! Run with: `cargo kani -p mish-ssp` (harnesses are `#[cfg(kani)]`, so they
//! never enter a normal `cargo build`/`cargo test`).
//!
//! The bounds (body length, fragment `count`, sequence length) are kept small on
//! purpose: the properties proved here — header decoding, the `index < count`
//! guard protecting `chunks[index]`, and the running `buffered` byte accounting
//! never underflowing — are *structural*; they don't depend on the magnitudes,
//! so a small bound that exercises every branch is a sound and tractable proof.

use crate::frag::{Defragmenter, Fragmenter, FRAGMENT_HEADER};

/// Largest fragment body we let the solver pick. The header is fixed-size, so a
/// few body bytes is enough to exercise the copy + byte-accounting paths.
const MAX_BODY: usize = 3;
/// Largest symbolic datagram: header + a small body.
const MAX_DATAGRAM: usize = FRAGMENT_HEADER + MAX_BODY;
/// Cap on the peer-declared fragment `count`. `push` does `vec![None; count]`, so
/// bounding it keeps the allocation and the completion loop finite for the solver
/// without weakening the (count-independent) safety properties.
const MAX_COUNT: u8 = 3;

/// Fill a fixed-size buffer with fully-symbolic bytes and return a symbolic,
/// in-bounds length for the prefix actually pushed.
fn symbolic_datagram(buf: &mut [u8; MAX_DATAGRAM]) -> usize {
    for b in buf.iter_mut() {
        *b = kani::any();
    }
    // Bound the peer-controlled `count` (datagram[4..6], little-endian u16) to a
    // small value so the reassembly table stays finite. High byte zero + low byte
    // capped ⇒ count ∈ 0..=MAX_COUNT. This constrains only the table *size*, never
    // which branches run, so every guard (count==0, index>=count, count mismatch,
    // single-fragment fast path, completion) remains reachable.
    kani::assume(buf[5] == 0);
    kani::assume(buf[4] <= MAX_COUNT);

    let len: usize = kani::any();
    kani::assume(len <= MAX_DATAGRAM);
    len
}

/// A single arbitrary datagram fed to a fresh `Defragmenter` never panics.
///
/// Proves, for *every* header/body within the bound: the short-datagram guard,
/// the `from_le_bytes` header decode, the `count == 0 || index >= count` reject,
/// the `chunks[index]` write (safe because of that guard), and the `buffered`
/// byte arithmetic all stay panic- and overflow-free.
#[kani::proof]
#[kani::unwind(16)]
#[kani::solver(kissat)]
fn push_single_datagram_never_panics() {
    let mut buf = [0u8; MAX_DATAGRAM];
    let len = symbolic_datagram(&mut buf);

    let mut defrag = Defragmenter::new();
    let _ = defrag.push(&buf[..len]);
}

/// A short *sequence* of arbitrary datagrams never panics.
///
/// This is the harness that reaches the multi-fragment paths a single push can't:
/// accumulation across pushes, the cross-fragment `count`-mismatch reject, the
/// completion branch (`received == count`) with its `remove().expect("just
/// inserted")` and `chunk.expect("all chunks present")`, and — critically — the
/// `self.buffered -= ...` subtractions on completion and eviction, which must
/// never underflow. Kani proves those two `expect`s are unreachable and the
/// accounting stays non-negative for every interleaving of three datagrams.
#[kani::proof]
#[kani::unwind(16)]
#[kani::solver(kissat)]
fn push_sequence_never_panics() {
    let mut defrag = Defragmenter::new();
    // Three datagrams is enough to open a reassembly, hit a duplicate/mismatch,
    // and complete it; more only multiplies state without new branches.
    for _ in 0..3 {
        let mut buf = [0u8; MAX_DATAGRAM];
        let len = symbolic_datagram(&mut buf);
        let _ = defrag.push(&buf[..len]);
    }
}

/// Honest round-trip: anything `Fragmenter` splits, `Defragmenter` rebuilds
/// exactly — proved for *every* payload and MTU within the bound.
///
/// The `frag_reassemble` fuzzer asserts this same property on sampled inputs;
/// here it is a complete result over the bounded domain (payloads up to
/// [`MAX_BODY`] bytes, MTUs spanning the single- and multi-fragment regimes).
#[kani::proof]
#[kani::unwind(16)]
#[kani::solver(kissat)]
fn fragment_roundtrip_is_lossless() {
    let mut payload = [0u8; MAX_BODY];
    for b in payload.iter_mut() {
        *b = kani::any();
    }
    let plen: usize = kani::any();
    kani::assume(plen <= MAX_BODY);

    // MTU from just above the header (forces the smallest 1-byte chunks, i.e. the
    // most fragments) up to comfortably one-shot — covering both the single- and
    // multi-fragment branches of `fragment`.
    let mtu: usize = kani::any();
    kani::assume(mtu >= FRAGMENT_HEADER + 1);
    kani::assume(mtu <= FRAGMENT_HEADER + MAX_BODY + 1);

    let mut frag = Fragmenter::new();
    let pieces = frag.fragment(&payload[..plen], mtu);

    let mut defrag = Defragmenter::new();
    let mut out = None;
    for p in &pieces {
        if let Some(payload) = defrag.push(p) {
            out = Some(payload);
        }
    }
    assert_eq!(
        out.as_deref(),
        Some(&payload[..plen]),
        "fragment/reassemble must round-trip exactly"
    );
}

// NOT proved here, on purpose — and a good illustration of Kani's boundary:
//
// * The hostile *memory bound* (`buffered_bytes()` stays under MAX_REASSEMBLY_BYTES
//   no matter the peer) is an inherently large-N property: it only bites after
//   many ids each declaring `count = 65535`. That's hundreds of pushes and an
//   8 MiB cap — far past any tractable unwind/allocation for a solver. It stays a
//   concrete unit test + the `frag_memory_bounds` fuzz target.
// * `instruction::decode`'s `bincode`/`inflate` interior is opaque to Kani; the
//   `instruction_decode` + `answerback_safety` fuzzers own that surface.
