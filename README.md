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

## Testing

| Layer | What | Where |
|-------|------|-------|
| Unit | `SyncState` contract, instruction codec, receiver idempotency/replay-safety | `src/*` `#[cfg(test)]`, `tests/core_unit.rs` |
| Property (PBT) | diff/apply round-trip & idempotency; convergence for *any* payload/loss/jitter/seed | `tests/proptest_ssp.rs` |
| Deterministic sim | two cores over a virtual lossy/reordering link, many seeds | `tests/sim_convergence.rs` |
| Async integration | real `Driver` event loop over in-memory transport, incl. 30% loss | `mish-ssp/tests/integration.rs` |
| QUIC e2e | full stack over real Quinn endpoints: two-way sync, 25% datagram loss recovery, client migration/roaming | `mish-quic/tests/quic_e2e.rs` |
| Terminal | screen-diff & user-stream PBTs, emulator VT parsing, client/server convergence over the sim (incl. 40% loss) | `mish-terminal/tests/*` |

```sh
cargo test          # everything
cargo clippy --all-targets
```

## Roadmap

- [x] **M1 — SSP core + transport/session traits.** Sans-IO `SspCore`,
      `SyncState`/`Transport`/`Session` traits, in-memory transport, virtual-time
      simulator, PBT + sim + async integration tests. *(done)*
- [ ] **M2 — RTT estimation & fragmentation.** Datagram-layer timestamp echo for
      SRTT/RTO; instruction fragmentation + chaff for the MTU.
- [x] **M3 — QUIC transport (`mish-quic`).** Quinn endpoint with the unreliable
      datagram extension implementing `Transport`; datagram-only connections
      (streams disabled); self-signed/insecure + trusted TLS configs; **client
      migration/roaming** verified; deterministic loss injection via a custom
      `AsyncUdpSocket` proving SSP heals QUIC datagram loss end-to-end. *(done)*
      *(Deferred: `turmoil`/`madsim` virtual-time sim of the QUIC layer — the
      deterministic core sim already covers protocol logic.)*
- [x] **M4 — Terminal layer (`mish-terminal`).** `Screen` (`Complete`) and
      `UserStream` `SyncState`s as pure data — row-granular screen diff,
      append-only/trimmable input log — plus an `alacritty-terminal`-backed
      `Emulator` that turns PTY bytes into `Screen` snapshots, and a full-frame
      ANSI `render`er. PBTs + emulator tests + client/server convergence over the
      simulator (incl. 40% loss). *(done)*
      *(Deferred: client-side predictive echo — mosh's `terminaloverlay`.)*
- [ ] **M5 — Binaries.** `mish-server` (PTY + child shell) and `mish-client`
      (raw TTY, resize, predictions), bootstrap handshake.
- [ ] **M6 — Shutdown handshake, key rotation, fuzzing, soak sims.**

## License

GPL-3.0-or-later, matching upstream mosh.
