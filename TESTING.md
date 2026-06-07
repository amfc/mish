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

### 14. Exhaustive bounded model checking — `mish-ssp/src/stateright_model.rs` (Stateright)
Where the sim (#2) drives the two real `SspCore`s through *one* random schedule
per seed, this drives them through **every** schedule interleaving up to a bounded
scenario length, via a [Stateright](https://www.stateright.rs/) `Model` whose
nondeterminism *is* the schedule (which datagram to deliver next, drop, duplicate;
when each side mutates its state). Runs as a plain `cargo test -p mish-ssp`
(`stateright_model::tests::*`), so it's covered by CI's `cargo test --workspace`.
- **Two link models:** an *adversarial* link (drop/dup/reorder) checks **safety** —
  `no_divergence` (a receiver never holds a value the sender never sent),
  `bounded_received`/`bounded_sent` (queue caps hold under sustained faults), and a
  `sometimes can_converge` non-vacuity guard; a *fair* link (reorder but eventual
  delivery, baked into the action policy) checks **liveness** — `eventually
  converge`. Last run: ~134k unique adversarial states, ~1.6k fair states.
- **Bounded, but a real theorem.** The real core has unbounded counters
  (`next_seq`, state `num`s, ms timers) and `f64` RTT, so there's no finite closed
  space. We bound the *scenario length* with a strictly-decreasing `steps_left`
  budget (which also keeps the graph acyclic — required for sound `eventually`) and
  exhaust all interleavings within it. The fingerprint (`Hash`/`Eq` on `SspCore`,
  `cfg(test)` in `core.rs`) is faithful — every behavior-affecting field including
  the `f64`s by bit pattern — so dedup never silently merges distinct cores.
- **Found:** `add_sent_state` computed its eviction index as `len - 16`, assuming
  `max_sent_states ≥ 16` (true for the default 32, so production never hit it). For
  any smaller cap it underflowed — a debug panic, and in release a wrap to a no-op
  `VecDeque::remove` that *leaks the memory bound*. Fixed to
  `len.saturating_sub(16).max(1)` (identical for the production cap; never evicts
  the acked front).

### 15. Mutation testing — `cargo mutants` (tests the tests)
Mutates the source (flip `<`→`<=`, delete a `?`, replace a fn body) and checks
whether any test fails; a *surviving* mutant is a line we execute but don't
assert on. Pointed at the parsers + SSP core (`core.rs`, `instruction.rs`,
`frag.rs`, `states.rs` — 292 mutants). Not in CI (slow, and needs the binary);
reproduce with the scratch dir off-`/tmp` (see learnings):

```
TMPDIR=$HOME/.cache/mutants-tmp cargo mutants -p mish-ssp \
  -f crates/mish-ssp/src/{core,instruction,frag,states}.rs -j 8 \
  -C --lib -C --test -C core_unit -C --test -C fuzz_decode -C --test -C fuzz_hostile \
  -C --test -C integration -C --test -C proptest_ssp -C --test -C sim_convergence
```
(The randomized `fuzz_driver_live` is excluded: nondeterministic tests are unsound
mutation oracles.)
- **Found + closed:** the latency-critical **RTT estimator math** (`Rtt::sample`/
  `rto`, ~32 mutants) had *no* assertions — convergence/model-check tests assert
  *that* it syncs and stays bounded but ignore timing, so any change to the
  Jacobson/Karels arithmetic survived. Added exact-value unit tests
  (`core::rtt_tests`). Also `BytesState::diff_from` was only round-trip-tested, so
  degrading `common_prefix_len` to `0` (reship the whole state) survived — added
  `diff_compresses_shared_prefix`.
- **Accepted survivors (triaged, not bugs):** the rest are (a) *timing/cadence
  internals* (`calculate_timers`, `send_interval`, `timestamp_reply`, `recv`'s RTT
  reorder-guard) that convergence legitimately doesn't depend on; (b) *perf knobs*
  (`attempt_prospective_resend` — a documented A/B optimization; `process_throwaway_until`
  GC, recovered by redundant resends); (c) *equivalent mutants* (`new_initial`
  ↔ `Default::default()` — `BytesState`'s default *is* the empty state, unkillable).
  Chasing these would pin perf/timing internals at high cost and low safety value.

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
- **`cargo mutants` copies the tree per parallel worker** into `$TMPDIR`. On this
  box `/tmp` is a small rootfs and the copy pulls in the multi-GB `fuzz/target/`
  (its nested `.gitignore` isn't honored), so it fills instantly — point `TMPDIR`
  at a roomy `/home` path. Each test run is ~50s (the suite), so use `-j` and
  exclude the long randomized `fuzz_driver_live`.
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
   - **Builtin (russh) bootstrap** (`--bootstrap=builtin`) is tested at four
     levels: (a) **unit** — `BootstrapMode` parsing, `program_on_path`,
     `split_user_host`, `shell_quote`; `~/.ssh/config` resolution + precedence
     (`resolve_from`), ProxyJump spec/chain parsing (`parse_jump_spec`,
     `split_proxy_jump`), `~` expansion, and **passphrase-protected key**
     decryption (`load_secret_key`/`load_identity` over an encrypted ed25519
     fixture: needs-passphrase signalled, right/wrong passphrase, non-interactive
     skip); (b) **security** — host-key verdicts (`classify_host_key`) against a
     temp `known_hosts` with real ed25519 keys proving a *changed* key is rejected
     and an unknown one is TOFU, `shell_quote` injection-resistance through a real
     `/bin/sh`, and the memory-**bounded** `MISH CONNECT` scanner (`scan_connect`);
     (c) **fuzz** — a proptest (`fuzz_parse_never_panics`,
     `scan_connect_stays_bounded`, `shell_quote_round_trips_through_split`) plus
     the coverage-guided `bootstrap_parse` libFuzzer target; (d) **e2e** —
     [`scripts/test-builtin-bootstrap.sh`](scripts/test-builtin-bootstrap.sh)
     runs the real client against a live sshd (throwaway key/agent, cleaned up):
     builtin + system-ssh transports both carry a command, `auto` falls back to
     builtin when `ssh` is absent, an unknown user is rejected, a `~/.ssh/config`
     alias resolves, and a **ProxyJump** tunnel (localhost as its own jump) works.
     The passphrase-prompt path is additionally verified end-to-end against the
     live sshd with an encrypted IdentityFile and no agent.
3. **`#38`** — *done.* PTY `IUTF8` flag set via the master fd
   (`pty::enable_iutf8`, `iutf8_set_via_master_reaches_slave`); three-leg
   shutdown handshake confirmed loss-tolerant
   (`core_unit::shutdown_converges_under_loss`). Initial winsize was already
   taken from the real terminal.
4. **`#35`** — SSP ECN throttle / prospective-resend / conditional idle shutdown.
   Largely subsumed by QUIC's congestion control; low value.
5. **`#39`** — *done.* Diff-engine throughput benchmark
   (`mish-terminal/examples/diff_bench.rs`, mosh's `benchmark.cc` equivalent —
   times `new_frame` + `apply_diff` round-trip) and a real-PTY reference harness
   (`mosh/tests/real_terminal_reference.rs` — real program on a real kernel PTY,
   cross-checked against the independent `vt100` renderer). A true tmux/xterm
   oracle is an optional future extension where those are installed.

Deferred sub-items inside finished work: DECSCNM reverse-video + legacy mouse
encodings (alacritty doesn't model them well); **zeroize the in-memory client
key** (ties to secrecy adoption); syslog / `SSH_CONNECTION` bind / utmp.
