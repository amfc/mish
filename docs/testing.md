# Testing and harnesses

How mish is tested, what each harness caught, and the tricky bits worth
remembering. For the security model see [`security.md`](security.md); for
deliberate non-goals see [`not-implementing.md`](not-implementing.md).

## The central invariant: round-trip identity

The whole diff/sync design rests on one property:

> `prev.clone().apply_diff(cur.diff_from(&prev)) == cur`

`diff_from` produces mosh's minimal escape stream (`display::new_frame`).
`apply_diff` reconstructs the screen by replaying that stream through a throwaway
alacritty emulator and snapshotting. So the diff is verified by an independent
mechanism, a real emulator, not by trusting the differ.

A consequence for contributors: every field added to `Screen` must survive an
emulator round-trip. It has to be produced by the emulator on `snapshot` and
emitted by `new_frame` such that replaying reproduces it. Fields that are
transient or monotonic need special care (see Learnings).

## The harnesses

Roughly cheapest to most expensive. Run everything with `cargo test --workspace`;
the nightly and sanitizer lanes are separate (see `.github/workflows/ci.yml`).

### 1. Unit and property tests (`proptest`)

Per-crate `#[cfg(test)]` plus `tests/proptest_ssp.rs` and `tests/state_sync.rs`.
Diff/apply round-trip and idempotency for arbitrary payloads.

Found: `Color::Named` truncated to `u8` aliased the default background (257) onto
red. Widened to `u16`.

### 2. Deterministic network simulation

`mish-ssp/src/sim.rs` plus `tests/sim_convergence.rs`. Two sans-IO `SspCore`s and
a fake link, driven in a tight loop over virtual time (no async, no real clock).
Same seed gives an identical run. Models loss, duplication, corruption, reorder,
asymmetric (per-direction) loss, and peer clock skew; asserts convergence and
bounded memory.

The asymmetric, skew, and soak scenarios are regression guards. Clock skew proved
the RTT math is skew-invariant. Corruption modeling clarified a subtlety (see
Learnings).

### 3. Async integration

`mish-ssp/tests/integration.rs`. The real `Driver` event loop over the in-memory
transport (real tokio, real channels), including 30% loss.

Found: the Driver busy-looped at 100% CPU on a closed local handle, the
always-ready `None` arm. Fixed by tracking `local_open`.

### 4. Concurrency / ThreadSanitizer

`mish-ssp/tests/concurrency.rs` plus `scripts/tsan.sh`. A multi-thread tokio test
hammering the Driver's shared channels and lossy relay tasks from several worker
threads, run under `-Zsanitizer=thread` with an instrumented std
(`-Zbuild-std`).

Found: a latent panic. `timeout()` did `.clamp(50, cfg.rto)`, which panics when
`cfg.rto < 50` (inverted range). Fixed to `clamp(min(50, rto), rto)`. No data
races in the Driver's shared state.

### 5. QUIC end-to-end

`mish-quic/tests/{quic_e2e,auth,wire_attacks}.rs`. Real quinn endpoints on
loopback. Two-way sync, 25% datagram-loss recovery (QUIC does not retransmit
datagrams, so SSP heals), migration.

Found: drove the fragmentation design (a full-screen diff exceeds the QUIC
datagram limit, so it must fragment). The security adversaries in
`wire_attacks.rs` use a custom fault-injecting `AsyncUdpSocket` (loss, dup,
corrupt, MTU-cap) to prove bit-flips are AEAD-rejected (session heals),
duplicates do not double-apply, off-path junk and pre-handshake floods do not
disrupt, and an MTU black hole still converges via DPLPMTUD-down plus
fragmentation.

### 6. Deterministic full stack (madsim)

`mish-madsim/tests/madsim_fullstack.rs` (`--cfg madsim`). Client, simulated UDP,
server, and a scripted shell, all under madsim, seed-reproducible. Transparency
(client screen equals shell output) under loss; single migration; a roaming storm
of 8 rapid migrations.

### 7. Transparency

`mish/tests/transparency.rs`. The client's reconstructed `Screen` must equal the
server's emulator `Screen` over the full stack. Sharper than tmux
capture-diffing.

### 8. Diff round-trip fuzzers

`mish-terminal/tests/fuzz_diff.rs` (structured VT-op sequences) and
`mish/tests/replay.rs` (a real shell's output, chunk by chunk).

Found: control-char cells emitted raw (desync), normalized to space; scroll
exposed lines colored with the active pen, so the pen is reset before scroll LFs;
the `F_WIDE`/`F_WIDE_SPACER` flags were redundant state that diverged on erase, so
width is now derived from `unicode-width`.

### 9. Hostile-peer and prediction fuzz

`mish-ssp/tests/fuzz_hostile.rs`, `mish-terminal/tests/fuzz_predict.rs`,
`mish-ssp/tests/fuzz_driver_live.rs`. Arbitrary or edge instructions, datagram
bytes, keystrokes, and a live-Driver garbage flood; assert no panic, bounded
memory, and that an honest exchange survives noise.

Found: `BytesState::apply_diff` `debug_assert!`'d on a too-short diff, fixed to
return and clamp. `PredictionEngine::reset()` cleared the UTF-8 decode buffer
mid-decode-loop, causing an out-of-bounds drain panic, fixed by leaving the
buffer alone.

### 10. Coverage-guided fuzzing (libFuzzer + ASan)

`fuzz/`. Targets include `instruction_decode`, `screen_apply`, `diff_roundtrip`
(emulator-driven, covers wide and combining chars), `frag_reassemble`,
`userstream_decode`, and `differential_emulator`. CI smoke-runs each and replays
the `fuzz/regressions/` seeds.

Found: `screen_apply` saw a diff header with a zero dimension (`0 x 59110`) slip
past the `cols*rows` cell-count guard (product 0) and panic alacritty's grid
building a zero-width row. Added a `cols == 0 || rows == 0` check; seed kept in
`fuzz/regressions/screen_apply/zero-dimension-grid-panic`. Also: the
`differential_emulator` harness's own input decoder read past the slice, caught by
the fuzzer; a bounds-safe `next()` fixed it.

### 11. Differential emulator vs `vt100`

`mish-terminal/tests/differential_emulator.rs` plus a fuzz target. Identical VT
streams go to the alacritty backend and the independent `vt100` crate; both must
render the same text and cursor. This checks correctness, not just
self-consistency.

Found: `CSI 1 J` (erase-above) with the cursor on row 1. alacritty leaves row 0
intact, vt100/xterm clear it. An inherited alacritty quirk, documented and
excluded from the equality grammar (see [`not-implementing.md`](not-implementing.md)).

### 12. Miri (UB / aliasing)

CI `miri` job. The index- and buffer-heavy sans-IO code (frag, instruction codec,
diff, SSP core, prediction overlay). Clean, no UB. It cannot run the tokio/PTY
layers; that is TSan's job.

### 13. Security tests

- `mish-quic/tests/auth.rs` plus `mish/tests/auth_e2e.rs`: mutual auth accepts the
  minted client and rejects no-cert, wrong client cert, and wrong server cert. The
  e2e cases run against the real binary.
- `config.rs::early_data_is_off`: 0-RTT (`max_early_data_size`) stays 0.
- `mish/tests/key_hygiene.rs`: the client key never appears in server stderr.
- `instruction.rs`: compression-bomb cap (`inflate_rejects_a_bomb`).

### 14. Exhaustive bounded model checking (Stateright)

`mish-ssp/src/stateright_model.rs`. Where the sim (#2) drives the two real
`SspCore`s through one random schedule per seed, this drives them through every
schedule interleaving up to a bounded scenario length, via a
[Stateright](https://www.stateright.rs/) `Model` whose nondeterminism is the
schedule: which datagram to deliver next, drop, or duplicate, and when each side
mutates its state. It runs as a plain `cargo test -p mish-ssp`, so CI's `cargo
test --workspace` covers it.

Two link models. An adversarial link (drop, dup, reorder) checks safety:
`no_divergence` (a receiver never holds a value the sender never sent),
`bounded_received`/`bounded_sent` (queue caps hold under sustained faults), and a
`sometimes can_converge` non-vacuity guard. A fair link (reorder but eventual
delivery) checks liveness: `eventually converge`. The last run explored roughly
134k unique adversarial states and 1.6k fair states.

The real core has unbounded counters (`next_seq`, state `num`s, ms timers) and
`f64` RTT, so there is no finite closed space. The scenario length is bounded with
a strictly decreasing `steps_left` budget, which also keeps the graph acyclic
(required for sound `eventually`), and all interleavings within it are exhausted.
The fingerprint (`Hash`/`Eq` on `SspCore`, `cfg(test)` in `core.rs`) is faithful,
covering every behavior-affecting field including the `f64`s by bit pattern, so
dedup never silently merges distinct cores.

Found: `add_sent_state` computed its eviction index as `len - 16`, assuming
`max_sent_states >= 16` (true for the default 32, so production never hit it). For
any smaller cap it underflowed, a debug panic, and in release a wrap to a no-op
`VecDeque::remove` that leaks the memory bound. Fixed to
`len.saturating_sub(16).max(1)` (identical for the production cap; never evicts
the acked front).

### 15. Mutation testing (`cargo mutants`)

Tests the tests. It mutates the source (flip `<` to `<=`, delete a `?`, replace a
fn body) and checks whether any test fails; a surviving mutant is a line that runs
but is not asserted on. Pointed at the parsers and SSP core (`core.rs`,
`instruction.rs`, `frag.rs`, `states.rs`, 292 mutants). Not in CI (slow, and needs
the binary); reproduce with the scratch dir off `/tmp`:

```
TMPDIR=$HOME/.cache/mutants-tmp cargo mutants -p mish-ssp \
  -f crates/mish-ssp/src/{core,instruction,frag,states}.rs -j 8 \
  -C --lib -C --test -C core_unit -C --test -C fuzz_decode -C --test -C fuzz_hostile \
  -C --test -C integration -C --test -C proptest_ssp -C --test -C sim_convergence
```

(The randomized `fuzz_driver_live` is excluded: nondeterministic tests are
unsound mutation oracles.)

Found and closed: the latency-critical RTT estimator math (`Rtt::sample`/`rto`,
~32 mutants) had no assertions. The convergence and model-check tests assert that
it syncs and stays bounded but ignore timing, so any change to the
Jacobson/Karels arithmetic survived. Added exact-value unit tests
(`core::rtt_tests`). Also `BytesState::diff_from` was only round-trip-tested, so
degrading `common_prefix_len` to `0` (reship the whole state) survived; added
`diff_compresses_shared_prefix`.

Accepted survivors (triaged, not bugs): timing and cadence internals
(`calculate_timers`, `send_interval`, `timestamp_reply`, `recv`'s RTT
reorder-guard) that convergence legitimately does not depend on; perf knobs
(`attempt_prospective_resend`, a documented A/B optimization;
`process_throwaway_until` GC, recovered by redundant resends); and equivalent
mutants (`new_initial` versus `Default::default()`, since `BytesState`'s default
is the empty state, unkillable). Chasing these would pin perf and timing
internals at high cost and low safety value.

## Learnings

- **Corruption on an authenticated wire is a drop, not garbage.** A bit-flip that
  still decoded to a valid instruction broke latest-wins convergence (a high
  `new_num` poison). That cannot happen in production: QUIC/TLS AEAD drops
  tampered packets. So the sim models corruption as an extra loss source. An
  attacker injecting well-formed malicious instructions is a separate threat,
  covered for safety and bounded memory by `fuzz_hostile`.
- **Monotonic and transient `Screen` fields need care in the round-trip model.**
  Clipboard (OSC 52) never reverts to `None` (the emulator listener keeps the
  last value), so an arbitrary `Some` then `None` pair is unreachable, excluded
  from `arb_screen` and covered by directional tests. Bell is a count; the diff
  emits the delta as BEL bytes and the receiver re-counts them, so it round-trips
  exactly. A full repaint re-rings accumulated bells (bounded, rare), accepted.
- **DECCKM "cursor-key translation" is just mode-replay.** mish does not rewrite
  arrow bytes. Syncing app-cursor-keys mode and replaying the DECSET onto the
  client's terminal makes it natively emit SS3 arrows, the same mechanism as
  bracketed-paste and mouse.
- **TLS 1.3 mutual-auth rejection is asynchronous.** The client's `connect().await`
  can succeed before the server's mandatory-client-auth rejection arrives, so the
  no-cert test asserts the connection then gets closed, not that `connect` fails.
- **TSan needs `-Zbuild-std`, nightly, and rust-src**, plus a multi-thread tokio
  runtime. `#[tokio::test]` defaults to current-thread, which hides cross-thread
  races. loom and shuttle do not fit: the concurrency is tokio's primitives, which
  they cannot instrument, and there is no hand-rolled lock-free code to model.
- **Compression is per-instruction and stateless by necessity.** Datagrams are
  unreliable and unordered, so a shared cross-message window would desync on the
  first loss. A preset dictionary (zlib `deflateSetDictionary`) is the lever for
  small-message ratio, and is on the roadmap.
- **Clock skew is invariant.** RTT uses per-peer clock domains plus wrapping
  16-bit timestamps and relative deltas, so a constant offset between peers'
  clocks cancels, proven by `converges_with_divergent_peer_clocks`. Separately,
  feeding non-monotonic `now` to the core overflowed timer adds, so all were
  converted to `saturating_add`.
- **`portable-pty` execs `argv[0]`**, so the classic `-bash` login-shell
  convention (program `/bin/bash`, argv[0] `-bash`) is not expressible; mish uses
  `$SHELL -l`.
- **Disk:** `-Zbuild-std` (TSan, Miri) roughly doubles the `target/` tree and once
  hit 100% disk; `cargo clean` reclaims it. CI uses a fresh runner, so it is fine.
- **`cargo mutants` copies the tree per parallel worker** into `$TMPDIR`. On this
  box `/tmp` is a small rootfs and the copy pulls in the multi-GB `fuzz/target/`
  (its nested `.gitignore` is not honored), so it fills instantly; point `TMPDIR`
  at a roomy `/home` path. Each test run is about 50s, so use `-j` and exclude the
  long randomized `fuzz_driver_live`.
- **Adding a `Screen` field means touching every `Screen { … }` literal in tests**
  (`state_sync.rs`, `display_roundtrip.rs`). Substring-edit the field block and
  let `cargo fmt` fix indentation.
