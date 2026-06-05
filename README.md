# mish

A reimplementation of [mosh](https://mosh.org/) (the mobile shell) in Rust, over
**QUIC unreliable datagrams** ([Quinn](https://github.com/quinn-rs/quinn)) with
the terminal layer provided by
[`alacritty-terminal`](https://crates.io/crates/alacritty_terminal).

By reusing QUIC for transport/crypto and `alacritty-terminal` for emulation, the
goal is far fewer lines than upstream mosh (~20k C++ + hand-rolled OCB crypto)
while matching its key property: **a roaming, low-latency shell that survives
packet loss, IP changes, and suspend/resume.**

**Status: working end-to-end and at mosh feature parity.** All seven milestones
(M1–M7) are done: the sans-IO SSP core, fragmentation + RTT estimation, the
mutually-authenticated QUIC transport, the `alacritty-terminal` layer with
mosh's minimal-diff, the `mish-client` / `mish-server` binaries, predictive
echo, and the deterministic network simulators. Several features now go *beyond*
upstream mosh — server-side **scrollback**, **persistent sessions + reattach**,
and a reliable QUIC **side-channel** (see [`NEXT_FEATURES.md`](NEXT_FEATURES.md)).
What's left (tracked in [`FUTURE_WORK.md`](FUTURE_WORK.md)) is small polish, not
core functionality.

## Why this can be small

Mosh's genius is the **State Synchronization Protocol (SSP)**: instead of a
reliable byte stream, each side keeps a copy of the *application state* and syncs
it by sending diffs over unreliable datagrams. There is no retransmit queue — a
lost datagram just means the next one re-diffs from further back. That design
maps perfectly onto QUIC's unreliable datagram extension, and QUIC gives us the
crypto, congestion control, and connection migration mosh had to build by hand.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│ mish-client / mish-server  (mish crate — done)           │
├─────────────────────────────────────────────────────────────┤
│ mish-terminal  (alacritty-terminal-backed SyncStates)        │
│    Complete (screen)   ·   UserStream (keystrokes)           │
│    + predictive echo overlay (mosh's terminaloverlay)        │
├─────────────────────────────────────────────────────────────┤
│ mish-ssp  (sans-IO protocol core)                            │
│   ┌──────────────┐   ┌─────────────────┐  ┌───────────────┐  │
│   │ SyncState    │   │ SspCore         │  │ Session/Driver│  │
│   │ trait        │──▶│ (sans-IO state  │◀─│ (async event  │  │
│   │ (diff/apply) │   │  machine)       │  │  loop)        │  │
│   └──────────────┘   └─────────────────┘  └───────┬───────┘  │
│                         ▲          ▲              │          │
│                  sim::NetworkSim   │       Transport trait   │
│                  (virtual-time     │      ┌───────┴───────┐  │
│                   simulator)       │      │ memory  │ quic │  │
│                                    │      │ (test)  │(done)│  │
└────────────────────────────────────┴──────┴───────┴──────┴──┘

Crates: mish-ssp (core) · mish-terminal (emulator + diff + predict) ·
mish-quic (Quinn transport) · mish (binaries) · mish-sim (turmoil) ·
mish-madsim (madsim). Both sim engines run the real session in virtual time.
```

### Design principle: sans-IO core

[`SspCore`](crates/mish-ssp/src/core.rs) — the faithful port of mosh's
`TransportSender` + receiver — does **no I/O and reads no clock**. Time is an
argument to every method; datagrams are returned as values. This makes the
protocol:

- **deterministic** — replayable from any input sequence,
- **simulation-friendly** — [`sim::NetworkSim`](crates/mish-ssp/src/sim.rs) runs
  two cores over a fake lossy link in virtual time, fully reproducible by seed,
- **transport-agnostic** — the async [`Driver`](crates/mish-ssp/src/session.rs)
  is a thin shell that pumps a `Transport` into the core.

This is the FoundationDB testing philosophy: push all nondeterminism to the
edges, then hammer the deterministic core.

## Usage

Like upstream mosh, `mish-client` bootstraps the session itself: it SSHes to the
host, starts `mish-server`, reads the `MISH CONNECT <port> <server-cert>
<client-cert> <client-key>` line it prints over the (authenticated) SSH channel,
then opens a **mutually-authenticated** QUIC/UDP session directly to that port.
The client pins the server cert *and* presents the minted client cert/key, so —
as in mosh's shared-key model — the server accepts input only from the party that
read those credentials over SSH. Anyone else who reaches the UDP port is rejected
at the TLS handshake.

```sh
# Remote (like `mosh host`): SSH in, start the server, attach over UDP.
mish-client user@host
mish-client user@host -- tmux attach     # run a specific command

# Local mode for testing: start mish-server as a child, no SSH.
mish-client --local
mish-client --local -- /bin/bash

# Options: --ssh <cmd>  --server <cmd>  --predict <mode>  --no-init
# Keys: Ctrl-] quick-detach; escape prefix Ctrl-^ (MOSH_ESCAPE_KEY) then
#       `.` quit / Ctrl-Z suspend (resumes cleanly on `fg`).
#       Mouse wheel (or Shift-PageUp/PageDown) scrolls into server-held scrollback.
```

**Scrollback (better than mosh).** Unlike upstream mosh — which has no
scrollback and tells you to run tmux — `mish-client` can scroll into the
server's terminal history with the **mouse wheel** (or **Shift-PageUp /
Shift-PageDown**). The live screen keeps riding loss-tolerant datagrams; history
is fetched on demand over a **reliable QUIC side-channel** and shown as a paused
viewport (any keystroke returns to live). See [`NEXT_FEATURES.md`](NEXT_FEATURES.md).

At the shell prompt the wheel scrolls *mosh's* scrollback; inside a full-screen
app (vim, less, htop…) it reaches the app as usual, so those keep their own
scrolling. To make this work the client turns on mouse reporting at the prompt,
which — as with tmux — means native click-drag text selection there now needs
the terminal's bypass modifier held (**Shift** on most terminals, **⌥/Option**
on macOS Terminal & iTerm2).

**Persistent sessions / reattach (also better than mosh).** With `--session
NAME`, the server keeps the shell + terminal state alive across disconnects, and
re-running `mish-client host --session NAME` **reattaches** to it (tmux/abduco-style)
— combined with QUIC roaming, that's the full "never lose your shell" story.
Opt-in; the default is a fresh session each time. (Reattach reuses the session's
credentials via a `0600` user-only registry file — see
[`SECURITY.md`](SECURITY.md).)

```sh
mish-client host --session work   # start (or reattach to) a persistent session "work"
```

A blue status banner ("mish: Last contact N seconds ago…") appears when the link
stalls, and the window title is prefixed `[mish]`.

`mish-server` (run on the remote by the bootstrap, or standalone) binds a UDP
port and prints `MISH CONNECT <port> <server-cert> <client-cert> <client-key>`
(hex) on stdout; everything else goes to stderr. It forces a UTF-8 locale for the
child shell. Over SSH it daemonizes (`--detach`: fork + setsid), so the SSH channel
closes while the server keeps serving and roaming across IP changes works over
the independent UDP/QUIC path.

## Non-goals

- **Wire compatibility with mosh.** This is intentionally *not* a drop-in for
  mosh's protocol: it uses QUIC unreliable datagrams with TLS 1.3 instead of
  mosh's UDP + hand-rolled OCB/AES, and a different instruction encoding. A
  mish client only talks to a mish server. We deliberately trade
  interoperability for reusing QUIC's crypto, congestion control, and connection
  migration.
- **Zero-RTT first paint.** QUIC's ~1-RTT handshake before the first datagram is
  expected and fine; the value is in everything QUIC gives us for free. (The
  *session* is still datagram-based and loss-tolerant after that.)

## Testing

| Layer | What | Where |
|-------|------|-------|
| Unit | `SyncState` contract, instruction codec, receiver idempotency/replay-safety | `src/*` `#[cfg(test)]`, `tests/core_unit.rs` |
| Property (PBT) | diff/apply round-trip & idempotency; convergence for *any* payload/loss/jitter/seed | `tests/proptest_ssp.rs` |
| Deterministic sim | two cores over a virtual lossy/reordering link, many seeds | `tests/sim_convergence.rs` |
| Async integration | real `Driver` event loop over in-memory transport, incl. 30% loss | `mish-ssp/tests/integration.rs` |
| QUIC e2e | full stack over real Quinn endpoints: two-way sync, 25% datagram loss recovery, client migration/roaming | `mish-quic/tests/quic_e2e.rs` |
| Terminal | screen-diff & user-stream PBTs, emulator VT parsing, client/server convergence over the sim (incl. 40% loss) | `mish-terminal/tests/*` |
| Fragmentation | split/reassemble round-trip, out-of-order, lost-fragment | `mish-ssp/src/frag.rs` |
| Full stack | headless loopback, real PTY shell, daemonization, SSH/local bootstrap, real QUIC + real PTY end-to-end | `mosh/tests/*` |
| Fuzz/robustness | no-panic on arbitrary wire bytes / screen diffs / VT input; hostile-peer instructions (bounded, no-panic) + prediction-engine fuzz | `*/tests/fuzz_*.rs` |
| Coverage-guided fuzz | libFuzzer + ASan targets (instruction decode, screen-diff apply, emulator-driven diff round-trip, fragment reassembler, UserStream decode, differential-vs-vt100) run as a CI smoke gate; checked-in regression seeds replayed first | `fuzz/` |
| Differential emulator | identical VT byte streams fed to our emulator and an independent one (`vt100`) must render the same screen + cursor | `mish-terminal/tests/differential_emulator.rs` |
| Real-PTY reference | output of a real program on a real kernel PTY rendered by our emulator and the independent `vt100` must agree (real bytes, independent oracle) | `mosh/tests/real_terminal_reference.rs` |
| Side-channel | reliable bidi-stream request/response over real QUIC: framed round-trip + a 256 KiB payload past the datagram limit | `mish-quic/tests/side_channel.rs`, `mish-ssp` `framing` |
| Scrollback | client fetches a deep history window over QUIC and gets the scrolled-off rows; client scroll-mode renders the history viewport headlessly | `mosh/tests/scrollback_e2e.rs`, `mosh/tests/scroll_client.rs` |
| Reattach | the persistent session survives a client detach and re-syncs the full screen (incl. gap output) to a fresh connection; a second `--session NAME` server reattaches via the registry | `mosh/tests/reattach.rs`, `mosh/tests/session_reattach.rs`, `mosh` `registry` |
| Diff-engine benchmark | throughput of `new_frame` + `apply_diff` round-trip across scrolling/typing/full-repaint workloads (mosh's `benchmark.cc`) | `mish-terminal/examples/diff_bench.rs` |
| Clock fuzz | non-monotonic / jumping / boundary clock values into the core's timer math: no panic, bounded memory, and forward jumps still converge | `mish-ssp/tests/fuzz_clock.rs` |
| Roaming | a client that migrates its source address mid-session keeps converging (server re-pins the peer) | `mish-madsim/tests/madsim_fullstack.rs` |
| Diff round-trip fuzz | structured-VT sequences + real-shell PTY replay, asserting the wire diff reproduces every screen transition | `mish-terminal/tests/fuzz_diff.rs`, `mosh/tests/replay.rs` |
| Transparency | client's reconstructed screen == server's emulator screen, over the full stack + deterministically under loss | `mosh/tests/transparency.rs` |
| Live-Driver fuzz | the async event loop survives a sustained garbage-datagram flood interleaved with honest traffic and still converges | `mish-ssp/tests/fuzz_driver_live.rs` |
| Fault soak | loss + duplication + corruption + reorder together, across many seeds, asserting convergence and bounded memory | `mish-ssp/tests/sim_convergence.rs` |
| madsim sim | sans-IO core, and full stack (scripted shell) over madsim's simulated UDP — reproducible by seed | `mish-madsim/tests/` |
| Miri (UB) | the sans-IO core (frag/codec/diff/SSP) and prediction overlay run clean under Miri — no UB or aliasing violations | CI `miri` job |
| Security: mutual auth | a client with no / wrong client cert is rejected (config + against the *real* server binary); a client rejects a wrong server cert; 0-RTT early data is off | `mish-quic/tests/auth.rs`, `mosh/tests/auth_e2e.rs`, `config.rs::early_data_is_off` |
| Security: wire attacks | bit-flipped datagram (AEAD-rejected → heals), duplicated datagram (no double-apply), off-path injection, and a pre-handshake junk flood can't disrupt/hijack/exhaust the session | `mish-quic/tests/wire_attacks.rs` |
| Security: key hygiene | the client private key never appears in the server's log (stderr) output | `mosh/tests/key_hygiene.rs` |

See **[`SECURITY.md`](SECURITY.md)** for the full threat model and what's
enforced/tested versus relied on QUIC (quinn) for (roaming-hijack path
validation, 3× anti-amplification).

The fuzz/round-trip harnesses earned their keep: they found and fixed several
real bugs — a Driver CPU spin on a closed handle, a screen-diff OOM on a
malformed header, control-character and scroll-with-pen diff corruption, the
wide-char model, a panic on a malformed `BytesState` diff, an out-of-bounds in
the prediction UTF-8 decoder, (via the libFuzzer `screen_apply` target) a
zero-dimension diff header that slipped past the cell-count guard and panicked
the emulator grid, and (via the clock fuzzer) timer-math add-overflows on
boundary timestamps — all now fixed and regression-guarded. (The
`screen_apply` crash artifact is promoted to a checked-in regression seed under
`fuzz/regressions/`, replayed by CI.)

```sh
cargo test          # everything
cargo clippy --all-targets
```

**vs. mosh's own tests:** mosh relies on tmux-driven end-to-end shell scripts
(emulation captures, e2e success/failure, repeat, a couple of network behaviors),
a handful of C++ unit tests (base64, OCB, encrypt/decrypt), and libFuzzer targets
for its VT parser. It has **no in-process network simulation**. mish ports the
equivalent emulation/e2e scenarios (see [`COVERAGE.md`](COVERAGE.md)) *and* adds
what mosh lacks: a sans-IO deterministic simulator, **two** network-simulation
engines (`turmoil` + `madsim`) running the real session under latency / loss /
partitions, and property-based + fuzz testing — all reproducible by seed. So on
the simulation/property axis our coverage is more complete; mosh's edge is years
of real-world exposure across many terminals and a larger hand-curated emulation
corpus.

See [`FUTURE_WORK.md`](FUTURE_WORK.md) for the remaining (mostly small)
differences from upstream mosh.

## Roadmap

All seven milestones below are **complete** — this is the build history, kept for
context. Forward work (features that go beyond mosh) lives in
[`NEXT_FEATURES.md`](NEXT_FEATURES.md); remaining polish in
[`FUTURE_WORK.md`](FUTURE_WORK.md).

- [x] **M1 — SSP core + transport/session traits.** Sans-IO `SspCore`,
      `SyncState`/`Transport`/`Session` traits, in-memory transport, virtual-time
      simulator, PBT + sim + async integration tests. *(done)*
- [x] **M2 — RTT estimation & fragmentation.** The `Driver` splits oversized
      instructions across MTU-sized datagrams and reassembles them
      (`mish_ssp::frag`), so full-screen diffs traverse QUIC; recovery is
      per-instruction (a lost fragment re-diffs the whole instruction), matching
      mosh. Instructions carry a 16-bit timestamp + echo; the core runs a
      Jacobson/Karels SRTT/RTTVAR estimator that scales the send interval and
      retransmit timeout (RFC 6298 / mosh's `Connection`). Each instruction is
      **deflate-compressed (zlib-rs)** behind a flag when it shrinks — fewer
      fragments, with a decompression-bomb cap. *(done. Deferred: length-disguising
      chaff — QUIC already pads/encrypts.)*
- [x] **M3 — QUIC transport (`mish-quic`).** Quinn endpoint with the unreliable
      datagram extension implementing `Transport`; datagram-only connections
      (streams disabled); **mutual-auth TLS** (pinned server + minted client cert)
      plus self-signed/insecure configs for tests; **client
      migration/roaming** verified; deterministic loss injection via a custom
      `AsyncUdpSocket` proving SSP heals QUIC datagram loss end-to-end. *(done)*
      *(Deferred: `turmoil`/`madsim` virtual-time sim of the QUIC layer — the
      deterministic core sim already covers protocol logic.)*
- [x] **M4 — Terminal layer (`mish-terminal`).** `Screen` (`Complete`) and
      `UserStream` `SyncState`s as pure data, an `alacritty-terminal`-backed
      `Emulator` (PTY bytes → `Screen`), and a faithful port of mosh's
      **`Display::new_frame`** minimal-diff (`display.rs`): cell-level change
      detection, ECH/EL blank runs, SGR-on-change, CR/LF/BS cursor optimization,
      whole-screen + DECSTBM scroll-region detection. Host **answerbacks**
      (DA/DSR/CPR/OSC-color/size queries) are captured and fed back to the child
      PTY, so programs that probe the terminal don't hang. It is both the SSP wire
      diff and the client's TTY paint, verified by round-trip identity (the check
      mosh runs in verbose mode). PBTs + the ported `emulation-*` suite +
      client/server convergence under loss. *(done)*
- [x] **M5 — Binaries (`mosh` crate).** `mish-server` (spawns a shell on a real
      PTY via `portable-pty`, feeds output through the emulator, applies the
      client's `UserStream` back to the PTY) and `mish-client` (raw TTY via
      `crossterm`, forwards keystrokes, repaints received screens, SIGWINCH
      resize, `Ctrl-]` detach, `Ctrl-^` escape + `Ctrl-Z` suspend with clean
      SIGCONT resume/repaint, and a "last contact" status banner on a stalled
      link). Session loops are transport-generic and
      I/O-decoupled, so they're tested headlessly; plus a real-PTY test and a
      **full-stack test** (real QUIC + real `/bin/sh` + emulator + render).
      The QUIC session is **mutually authenticated**: `mish-server` mints a
      per-session client cert/key, ships it (with the server cert) over the
      authenticated SSH `MISH CONNECT` line, and pins it — so only the
      SSH-authenticated party can connect or inject input. Verified by positive
      and negative security tests in `mish-quic/tests/auth.rs`. *(done)*
- [x] **M6 — Predictive echo + deterministic network simulation.**
      Client-side speculative echo (`mish-terminal/src/predict.rs`, mosh's
      `terminaloverlay`): overlays predicted keystrokes, validates/culls them
      against the server's `echo_ack`, flushes on misprediction, decodes complete
      UTF-8 before predicting (the `prediction-unicode` regression), abandons on
      escape sequences. Plus **`mish-sim`**: the real async session over
      `turmoil`-simulated UDP with latency, loss, partitions, and a controllable
      clock. Predictive echo is **adaptive** (SRTT-gated, mosh's default) with
      tentative predictions underlined and glitch suppression. *(done)*

See [`COVERAGE.md`](COVERAGE.md) for the mapping of mosh's own test suite to the
mish equivalents.

- [x] **M7 — Fidelity & hardening.** Server **daemonization** (fork/setsid, so
      SSH can close); **combining marks + wide (CJK) chars** carried through the
      diff; **clean shutdown handshake** (SHUTDOWN_NUM); **bracketed-paste / mouse
      / cursor-style** modes synced; **OSC 8 hyperlinks**; **scroll-detection +
      minimal-SGR** diff; `mish-server` **`-p` port range / `-l` locale /
      signal-timeout**; a **`madsim`** deterministic engine (`mish-madsim`,
      `--cfg madsim`) alongside turmoil; **fuzz/robustness** tests (proptest
      no-panic on arbitrary wire/diff bytes, plus **coverage-guided `cargo-fuzz`**
      targets run under ASan in CI); builds on **stable** Rust with a **GitHub
      Actions CI** (fmt/clippy/test + madsim + Miri + coverage + fuzz). *(done)*

### Beyond parity

With mosh parity reached, the forward roadmap — features that make mish
*better than* mosh by exploiting QUIC's reliable streams and crypto/resumption
(server-side **scrollback**, **session persistence + reattach**, **multi-client
attach**, large-payload **clipboard**, **congestion-aware pacing**, and **port
forwarding**) — is laid out in **[`NEXT_FEATURES.md`](NEXT_FEATURES.md)**.

## Toolchain, fuzzing & CI

Builds on stable Rust (pinned in `rust-toolchain.toml`). CI
(`.github/workflows/ci.yml`) runs `fmt`/`clippy`/`test` and the madsim engine.

```sh
cargo test                                   # everything (stable)
RUSTFLAGS="--cfg madsim" cargo test -p mish-madsim   # deterministic madsim sim
cargo +nightly fuzz run screen_apply         # one cargo-fuzz target (needs cargo-fuzz)
cargo +nightly miri test -p mish-ssp --lib   # UB/aliasing check on the sans-IO core
```

There are six coverage-guided libFuzzer targets (`instruction_decode`,
`screen_apply`, `diff_roundtrip`, `frag_reassemble`, `userstream_decode`,
`differential_emulator`). CI smoke-runs each for 40 s as a regression gate; for a
real campaign, **[`scripts/fuzz-overnight.sh`](scripts/fuzz-overnight.sh)** runs
all of them at once in libFuzzer fork mode, saturating every core and surviving
crashes (each saved, fuzzing continues), with a per-target time budget:

```sh
./scripts/fuzz-overnight.sh                  # all targets, ~8h each, all cores
DURATION=3600 ./scripts/fuzz-overnight.sh    # shorter run (1h)
./scripts/fuzz-overnight.sh diff_roundtrip   # a single target
```

## License

GPL-3.0-or-later, matching upstream mosh.
