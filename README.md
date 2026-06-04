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
to stderr. `mish` does not yet daemonize the server, so the SSH channel stays
open for the session (upstream mosh detaches it); roaming across IP changes still
works because the data path is independent UDP.

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
| Full stack | headless loopback, real PTY shell, and real QUIC + real PTY end-to-end | `mosh/tests/*` |

```sh
cargo test          # everything
cargo clippy --all-targets
```

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
      clock. *(done. Deferred: SRTT-gated/underlined prediction display — a
      refinement on *when* predictions show.)*

See [`COVERAGE.md`](COVERAGE.md) for the mapping of mosh's own test suite to the
mish equivalents.

- [ ] **M7 — Polish.** Server signal-timeout, flow-control/pty-deadlock test,
      shutdown handshake, hyperlink (OSC 8) modeling, `madsim` sim mode.

## License

GPL-3.0-or-later, matching upstream mosh.
