# mish

A reimplementation of [mosh](https://mosh.org/) (the mobile shell) in Rust, over
**QUIC unreliable datagrams** ([Quinn](https://github.com/quinn-rs/quinn)) with
the terminal layer provided by
[`alacritty-terminal`](https://crates.io/crates/alacritty_terminal).

By reusing QUIC for transport/crypto and `alacritty-terminal` for emulation, the
goal is far fewer lines than upstream mosh (~20k C++ + hand-rolled OCB crypto)
while matching its key property: **a roaming, low-latency shell that survives
packet loss, IP changes, and suspend/resume.**

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
│ mish-client / mish-server  (binaries — TODO)                 │
├─────────────────────────────────────────────────────────────┤
│ mish-terminal  (alacritty-terminal-backed SyncStates — TODO) │
│    Complete (screen)   ·   UserStream (keystrokes)           │
├─────────────────────────────────────────────────────────────┤
│ mish-ssp  (this crate)                                       │
│   ┌──────────────┐   ┌─────────────────┐  ┌───────────────┐  │
│   │ SyncState    │   │ SspCore         │  │ Session/Driver│  │
│   │ trait        │──▶│ (sans-IO state  │◀─│ (async event  │  │
│   │ (diff/apply) │   │  machine)       │  │  loop)        │  │
│   └──────────────┘   └─────────────────┘  └───────┬───────┘  │
│                         ▲          ▲              │          │
│                  sim::NetworkSim   │       Transport trait   │
│                  (virtual-time     │      ┌───────┴───────┐  │
│                   simulator)       │      │ memory  │ quic │  │
│                                    │      │ (now)   │(TODO)│  │
└────────────────────────────────────┴──────┴───────┴──────┴──┘
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
host, starts `mish-server`, reads the `MISH CONNECT <port> <cert>` line it prints
over the (authenticated) SSH channel, then opens the QUIC/UDP session directly to
that port — trusting exactly that certificate.

```sh
# Remote (like `mosh host`): SSH in, start the server, attach over UDP.
mish-client user@host
mish-client user@host -- tmux attach     # run a specific command

# Local mode for testing: start mish-server as a child, no SSH.
mish-client --local
mish-client --local -- /bin/bash

# Options: --ssh <cmd>  --server <cmd>     (Ctrl-] to detach)
```

`mish-server` (run on the remote by the bootstrap, or standalone) binds a UDP
port and prints `MISH CONNECT <port> <hex-cert>` on stdout; everything else goes
to stderr. Over SSH it daemonizes (`--detach`: fork + setsid), so the SSH channel
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
| Coverage-guided fuzz | libFuzzer + ASan targets (decode, screen-diff apply, emulator-driven diff round-trip) run as a CI smoke gate | `fuzz/` |
| Differential emulator | identical VT byte streams fed to our emulator and an independent one (`vt100`) must render the same screen + cursor | `mish-terminal/tests/differential_emulator.rs` |
| Diff round-trip fuzz | structured-VT sequences + real-shell PTY replay, asserting the wire diff reproduces every screen transition | `mish-terminal/tests/fuzz_diff.rs`, `mosh/tests/replay.rs` |
| Transparency | client's reconstructed screen == server's emulator screen, over the full stack + deterministically under loss | `mosh/tests/transparency.rs` |
| Live-Driver fuzz | the async event loop survives a sustained garbage-datagram flood interleaved with honest traffic and still converges | `mish-ssp/tests/fuzz_driver_live.rs` |
| Fault soak | loss + duplication + corruption + reorder together, across many seeds, asserting convergence and bounded memory | `mish-ssp/tests/sim_convergence.rs` |
| madsim sim | sans-IO core, and full stack (scripted shell) over madsim's simulated UDP — reproducible by seed | `mish-madsim/tests/` |
| Miri (UB) | the sans-IO core (frag/codec/diff/SSP) and prediction overlay run clean under Miri — no UB or aliasing violations | CI `miri` job |

The fuzz/round-trip harnesses earned their keep: they found and fixed several
real bugs — a Driver CPU spin on a closed handle, a screen-diff OOM on a
malformed header, control-character and scroll-with-pen diff corruption, the
wide-char model, a panic on a malformed `BytesState` diff, an out-of-bounds in
the prediction UTF-8 decoder, and (via the libFuzzer `screen_apply` target) a
zero-dimension diff header that slipped past the cell-count guard and panicked
the emulator grid.

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

- [x] **M1 — SSP core + transport/session traits.** Sans-IO `SspCore`,
      `SyncState`/`Transport`/`Session` traits, in-memory transport, virtual-time
      simulator, PBT + sim + async integration tests. *(done)*
- [x] **M2 — RTT estimation & fragmentation.** The `Driver` splits oversized
      instructions across MTU-sized datagrams and reassembles them
      (`mish_ssp::frag`), so full-screen diffs traverse QUIC; recovery is
      per-instruction (a lost fragment re-diffs the whole instruction), matching
      mosh. Instructions carry a 16-bit timestamp + echo; the core runs a
      Jacobson/Karels SRTT/RTTVAR estimator that scales the send interval and
      retransmit timeout (RFC 6298 / mosh's `Connection`). *(done. Deferred:
      length-disguising chaff — QUIC already pads/encrypts.)*
- [x] **M3 — QUIC transport (`mish-quic`).** Quinn endpoint with the unreliable
      datagram extension implementing `Transport`; datagram-only connections
      (streams disabled); self-signed/insecure + trusted TLS configs; **client
      migration/roaming** verified; deterministic loss injection via a custom
      `AsyncUdpSocket` proving SSP heals QUIC datagram loss end-to-end. *(done)*
      *(Deferred: `turmoil`/`madsim` virtual-time sim of the QUIC layer — the
      deterministic core sim already covers protocol logic.)*
- [x] **M4 — Terminal layer (`mish-terminal`).** `Screen` (`Complete`) and
      `UserStream` `SyncState`s as pure data, an `alacritty-terminal`-backed
      `Emulator` (PTY bytes → `Screen`), and a faithful port of mosh's
      **`Display::new_frame`** minimal-diff (`display.rs`): cell-level change
      detection, ECH/EL blank runs, SGR-on-change, CR/LF/BS cursor optimization.
      It is both the SSP wire diff and the client's TTY paint, verified by
      round-trip identity (the check mosh runs in verbose mode). PBTs + the ported
      `emulation-*` suite + client/server convergence under loss. *(done)*
- [x] **M5 — Binaries (`mosh` crate).** `mish-server` (spawns a shell on a real
      PTY via `portable-pty`, feeds output through the emulator, applies the
      client's `UserStream` back to the PTY) and `mish-client` (raw TTY via
      `crossterm`, forwards keystrokes, repaints received screens, SIGWINCH
      resize, `Ctrl-]` detach). Session loops are transport-generic and
      I/O-decoupled, so they're tested headlessly; plus a real-PTY test and a
      **full-stack test** (real QUIC + real `/bin/sh` + emulator + render).
      *(done. Deferred: SSH-bootstrapped certs — the demo uses insecure TLS
      verification.)*
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

## Toolchain, fuzzing & CI

Builds on stable Rust (pinned in `rust-toolchain.toml`). CI
(`.github/workflows/ci.yml`) runs `fmt`/`clippy`/`test` and the madsim engine.

```sh
cargo test                                   # everything (stable)
RUSTFLAGS="--cfg madsim" cargo test -p mish-madsim   # deterministic madsim sim
cargo +nightly fuzz run screen_apply         # cargo-fuzz target (needs cargo-fuzz)
cargo +nightly miri test -p mish-ssp --lib   # UB/aliasing check on the sans-IO core
```

## License

GPL-3.0-or-later, matching upstream mosh.
