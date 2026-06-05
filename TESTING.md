# Testing, harnesses & learnings

A guide to how mish is tested, what each harness actually caught, the tricky
bits worth remembering, and the remaining to-do list. (For the feature roadmap
see `FUTURE_WORK.md`; for the security model see `SECURITY.md`; for deliberate
non-goals see `NOT_IMPLEMENTING.md`.)

## The central invariant: round-trip identity

The whole diff/sync design rests on one property:

> `prev.clone().apply_diff(cur.diff_from(&prev)) == cur`

`diff_from` produces mosh's minimal escape stream (`display::new_frame`);
`apply_diff` reconstructs the screen by **replaying that stream through a
throwaway alacritty emulator** and snapshotting. So the diff is verified by an
*independent* mechanism (a real emulator), not by trusting the differ.

**Consequence for contributors:** every field added to `Screen` must survive an
emulator round-trip — it has to be (a) produced by the emulator on `snapshot`
and (b) emitted by `new_frame` such that replaying reproduces it. Fields that are
*transient* or *monotonic* need special care (see learnings).

## The harnesses (and what each found)

Roughly cheap→expensive. Run everything with `cargo test --workspace`; the
nightly/sanitizer lanes are separate (see CI `.github/workflows/ci.yml`).

### 1. Unit + property tests (`proptest`)
Per-crate `#[cfg(test)]` plus `tests/proptest_ssp.rs`, `tests/state_sync.rs`.
Diff/apply round-trip and idempotency for arbitrary payloads.
- **Found:** `Color::Named` truncated to `u8` aliased the default background (257)
  onto red — widened to `u16`.

### 2. Deterministic network simulation — `mish-ssp/src/sim.rs` + `tests/sim_convergence.rs`
Two sans-IO `SspCore`s + a fake link, driven in a tight loop over **virtual
time** (no async, no real clock). Same seed ⇒ identical run. Models loss,
duplication, corruption, reorder, **asymmetric (per-direction) loss**, and
**peer clock skew**; asserts convergence + bounded memory.
- **Found:** confirmed convergence holds under combined faults; the asymmetric/
  skew/soak scenarios are regression guards (clock skew proved the RTT math is
  skew-invariant). Corruption modeling clarified a subtlety (see learnings).

### 3. Async integration — `mish-ssp/tests/integration.rs`
The real `Driver` event loop over the in-memory transport (real tokio, real
channels), incl. 30% loss.
- **Found (earlier):** the Driver busy-looped (100% CPU) on a closed local
  handle — the always-ready `None` arm. Fixed by tracking `local_open`.

### 4. Concurrency / ThreadSanitizer — `mish-ssp/tests/concurrency.rs` + `scripts/tsan.sh`
A **multi-thread** tokio test hammering the Driver's shared channels + lossy
relay tasks from several worker threads, run under `-Zsanitizer=thread` with an
instrumented std (`-Zbuild-std`).
- **Found:** a latent panic — `timeout()` did `.clamp(50, cfg.rto)`, which panics
  when `cfg.rto < 50` (inverted range). Fixed to `clamp(min(50, rto), rto)`.
- **No data races** in the Driver's shared state.

### 5. QUIC end-to-end — `mish-quic/tests/{quic_e2e,auth,wire_attacks}.rs`
Real quinn endpoints on loopback. Two-way sync, 25% datagram-loss recovery
(QUIC does *not* retransmit datagrams — SSP heals), migration.
- **Found:** drove the fragmentation design (a full-screen diff exceeds the QUIC
  datagram limit → must fragment).
- Security adversaries (`wire_attacks.rs`): a custom fault-injecting
  `AsyncUdpSocket` (loss/dup/**corrupt**/**MTU-cap**) proves bit-flips are
  AEAD-rejected (session heals), duplicates don't double-apply, off-path junk and
  pre-handshake floods don't disrupt, and an MTU black hole still converges via
  DPLPMTUD-down + fragmentation.

### 6. Deterministic full stack — `mish-madsim/tests/madsim_fullstack.rs` (`--cfg madsim`)
Client + simulated UDP + server + a scripted shell, all under madsim, seed-
reproducible. Transparency (client screen == shell output) under loss; single
migration; **roaming storm** (8 rapid migrations).

### 7. Transparency — `mosh/tests/transparency.rs`
The client's reconstructed `Screen` must equal the server's emulator `Screen`
over the full stack (sharper than tmux capture-diffing).

### 8. Diff round-trip fuzzers
- `mish-terminal/tests/fuzz_diff.rs`: structured VT-op sequences.
- `mosh/tests/replay.rs`: a real shell's output, chunk by chunk.
- **Found:** control-char cells emitted raw (desync) → normalize to space; scroll
  exposed lines colored with the active pen → reset pen before scroll LFs; the
  `F_WIDE`/`F_WIDE_SPACER` flags were redundant state that diverged on erase →
  switched to deriving width from `unicode-width`.

### 9. Hostile-peer + prediction fuzz — `mish-ssp/tests/fuzz_hostile.rs`, `mish-terminal/tests/fuzz_predict.rs`, `mish-ssp/tests/fuzz_driver_live.rs`
Arbitrary/edge instructions, datagram bytes, keystrokes, and a live-Driver
garbage flood — assert no panic, bounded memory, honest exchange survives noise.
- **Found:** `BytesState::apply_diff` `debug_assert!`'d on a too-short diff →
  return + clamp. `PredictionEngine::reset()` cleared the UTF-8 decode buffer
  mid-decode-loop → out-of-bounds drain panic → leave the buffer alone.

### 10. Coverage-guided fuzzing (libFuzzer + ASan) — `fuzz/`
Targets: `instruction_decode`, `screen_apply`, `diff_roundtrip` (emulator-driven,
covers wide/combining), `frag_reassemble`, `userstream_decode`,
`differential_emulator`. CI smoke-runs each + replays `fuzz/regressions/` seeds.
- **Found:** `screen_apply` — a diff header with a **zero dimension** (`0 × 59110`)
  slipped past the `cols*rows` cell-count guard (product 0) and panicked
  alacritty's grid building a zero-width row → added `cols == 0 || rows == 0`.
  Seed kept in `fuzz/regressions/screen_apply/zero-dimension-grid-panic`.
- **Found:** the `differential_emulator` *harness's own* input decoder read past
  the slice — caught by the fuzzer (a bounds-safe `next()` fixed it).

### 11. Differential emulator vs `vt100` — `mish-terminal/tests/differential_emulator.rs` + fuzz target
Identical VT streams to our alacritty backend and the independent `vt100` crate;
assert the same rendered text + cursor (checks *correctness*, not just self-
consistency).
- **Found:** `CSI 1 J` (erase-above) with the cursor on row 1 — alacritty leaves
  row 0 intact, vt100/xterm clear it. An inherited alacritty quirk; documented and
  excluded from the equality grammar (see `NOT_IMPLEMENTING.md`).

### 12. Miri (UB / aliasing) — CI `miri` job
The index/buffer-heavy sans-IO code (frag, instruction codec, diff, SSP core,
prediction overlay). Clean — no UB. Can't run the tokio/PTY layers (that's TSan).

### 13. Security tests
- `mish-quic/tests/auth.rs` + `mosh/tests/auth_e2e.rs`: mutual auth accepts the
  minted client, rejects no-cert / wrong client cert / wrong server cert — the
  e2e ones against the **real binary**.
- `config.rs::early_data_is_off`: 0-RTT (`max_early_data_size`) stays 0.
- `mosh/tests/key_hygiene.rs`: the client key never appears in server stderr.
- `instruction.rs`: compression-bomb cap (`inflate_rejects_a_bomb`).

## Learnings / tricky bits

- **Corruption on an authenticated wire = a drop, not garbage.** A bit-flip that
  still *decoded* to a valid instruction broke latest-wins convergence (a
  high-`new_num` poison). But that can't happen in production: QUIC/TLS AEAD drops
  tampered packets. So the sim models corruption as an extra loss source; an
  attacker injecting *well-formed* malicious instructions is a separate threat,
  covered (for safety/bounded-memory) by `fuzz_hostile`.
- **Monotonic / transient `Screen` fields need care in the round-trip model.**
  - *Clipboard* (OSC 52) never reverts to `None` (the emulator listener keeps the
    last value), so an arbitrary `Some→None` pair is unreachable — excluded from
    `arb_screen`, covered by directional tests.
  - *Bell* is a count; the diff emits the **delta** as BEL bytes and the receiver
    re-counts them, so it round-trips exactly. A full repaint re-rings accumulated
    bells (bounded, rare) — accepted.
- **DECCKM "cursor-key translation" is just mode-replay.** We don't rewrite arrow
  bytes. Syncing app-cursor-keys mode and replaying the DECSET onto the *client's*
  terminal makes it natively emit SS3 arrows — same mechanism as bracketed-paste/
  mouse. Clean and correct.
- **TLS 1.3 mutual-auth rejection is asynchronous.** The client's `connect().await`
  can succeed before the server's mandatory-client-auth rejection arrives, so the
  no-cert test asserts the connection then gets *closed*, not that `connect` fails.
- **TSan needs `-Zbuild-std` + nightly + rust-src**, and a **multi-thread** tokio
  runtime — `#[tokio::test]` defaults to current-thread, which hides cross-thread
  races. **loom/shuttle don't fit:** our concurrency is tokio's primitives, which
  they can't instrument, and there's no hand-rolled lock-free code to model.
- **Compression is per-instruction and stateless by necessity.** Datagrams are
  unreliable/unordered, so a shared cross-message window would desync on the first
  loss. A *preset dictionary* (zlib `deflateSetDictionary`) is the lever for
  small-message ratio — deferred.
- **Clock skew is invariant.** RTT uses per-peer clock domains + wrapping 16-bit
  timestamps and relative deltas, so a constant offset between peers' clocks
  cancels — proven by `converges_with_divergent_peer_clocks`. Separately, feeding
  *non-monotonic* `now` to the core overflowed timer adds → all converted to
  `saturating_add`.
- **`portable-pty` execs `argv[0]`**, so the classic `-bash` login-shell convention
  (program `/bin/bash`, argv[0] `-bash`) isn't expressible; we use `$SHELL -l`.
- **Disk:** `-Zbuild-std` (TSan/Miri) roughly doubles the `target/` tree — it hit
  100% disk once; `cargo clean` reclaims it. CI uses a fresh runner so it's fine.
- **Adding a `Screen` field means touching every `Screen { … }` literal in tests**
  (`state_sync.rs`, `display_roundtrip.rs`). Substring-edit the field block and let
  `cargo fmt` fix indentation.

## Remaining to-do (next session)

All lower-value polish — no correctness or security stakes remain. Ranked:

1. **`#34` Prediction polish** — *done.* Paste guard (a single input batch over
   `PASTE_THRESHOLD` = 100 bytes resets the overlay and isn't predicted, mosh's
   `stmclient.cc` guard); predicted-cursor validation against the server cursor
   (a confirmed cursor that doesn't match resyncs, mosh's
   `ConditionalCursorMove::get_validity` — no more stuck mispredicted cursor);
   time-based glitch trigger (a prediction pending past `GLITCH_THRESHOLD` =
   250 ms forces the overlay on even on a fast-SRTT link, and past
   `GLITCH_FLAG_THRESHOLD` = 5 s also underlines, so typing never appears to
   vanish on a stall; quick confirmations cure the trigger). The engine now
   takes `now_ms` (sans-IO time-as-argument, like the SSP core) and the client
   drives aging via `advance(now)` on every repaint (incl. the idle banner
   tick, the role of mosh's 50 ms `wait_time()`). Tested in `predict.rs`
   (`paste_guard_skips_bulk_input`, `cursor_misprediction_triggers_resync`,
   `long_pending_prediction_forces_display`,
   `severe_glitch_underlines_even_with_flagging_off`,
   `quick_confirmations_cure_glitch_trigger`) and exercised by `fuzz_predict.rs`.
   *Deferred: `predict_overwrite` (insert-vs-overwrite shift) and
   `PredictMode::Experimental`.*
2. **`#37` CLI/bootstrap parity** — *client done.* `--ssh` shell-splitting +
   `ssh -n`/`-tt` + `--no-ssh-pty`, `--predict`/`-a`/`-n` +
   `MOSH_PREDICTION_DISPLAY`, `--no-init` (`MOSH_NO_TERM_INIT`), `--version`.
   `bootstrap::shell_split` (unit-tested) + `client_cli.rs` (version/help/bad-
   predict/missing-host). *Remaining: server `--version`/`--help`, `-c` color
   advertise.*
3. **`#38`** — PTY `IUTF8` flag (may be blocked by portable-pty), three-leg
   shutdown-handshake parity. (Initial winsize is already taken from the real
   terminal.)
4. **`#35`** — SSP ECN throttle / prospective-resend / conditional idle shutdown.
   Largely subsumed by QUIC's congestion control; low value.
5. **`#39`** — real-terminal (PTY-driven) reference harness + diff-engine
   throughput benchmark (mosh's `benchmark.cc`). Dev tooling.

Deferred sub-items inside finished work: DECSCNM reverse-video + legacy mouse
encodings (alacritty doesn't model them well); **zeroize the in-memory client
key** (ties to secrecy adoption); syslog / `SSH_CONNECTION` bind / utmp.
