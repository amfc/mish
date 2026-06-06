# bench-harness — mish vs mosh A/B latency harness

Drives **mish** and **upstream mosh** through the *same* fault-injecting
loopback UDP relay and measures both, identically, so the two are compared under
matched network impairment.

## What it measures

- **Display latency** (one-way, server→client): a child program (`bench-child`)
  paints a wall-clock marker every 30 ms; the harness reads it off the client's
  reconstructed screen and subtracts. Both processes share the machine clock.
- **Keyboard latency** (round-trip echo): the harness types a character into the
  client and times until it appears on the client's screen. The server child is
  `cat`, whose PTY line discipline echoes input — so the sample is a full
  client→server→client round trip.

Each is run with predictive echo **off** and **on**.

## How it works

- A small UDP relay sits in front of the server and drops/delays datagrams per a
  seeded fault model. It is L4-transparent, so QUIC (mish) and UDP/OCB (mosh)
  see identical loss/latency/jitter.
- Clients run in real PTYs (`portable-pty`); their output is fed to a
  `mish_terminal::Emulator` to reconstruct the on-screen text.
- mish is driven via `mish-client --attach IP PORT` (a raw direct-connect
  mode, credentials in `$MISH_CONNECT`); mosh via `mosh-client` + `$MOSH_KEY`.

It is real wall-clock (not the deterministic sim), so results are medians/p90
over repeated trials.

## Running

```sh
cargo build --release            # build mish-{server,client} + bench-child
cargo run -p bench-harness --release --bin bench-harness
```

`mosh-server`/`mosh-client` must be on `PATH` for the comparison rows (otherwise
the harness runs mish-only). `BENCH_DIRECT=1` bypasses the relay (connect
straight to the server) — useful to separate transport faults from behavior.

## Example results

Representative run (loopback, **release build** — always benchmark release: a
debug mish vs the release system `mosh` is an unfair comparison and inflates
mish by ~5 ms). Absolute numbers are machine-dependent; read the
mish-vs-mosh *gap*, not the raw values:

```
=== LAN    (rtt~2ms,  0% loss) ===
  DISPLAY (server→client, predict off)   KEYBOARD echo (predict off / on)
   mish:   15.9/  17.6 ms               27.9 ms /    2.2 ms
     mosh:   12.5/  13.5 ms               12.7 ms /    2.4 ms

=== WAN    (rtt~80ms, 5% loss) ===
   mish:   64.1/  74.3 ms              112.2 ms /    2.2 ms
     mosh:   59.6/  72.1 ms               55.2 ms /   53.3 ms

=== LOSSY  (rtt~120ms, 15% loss) ===
   mish:   87.4/ 103.3 ms              165.4 ms /    2.2 ms
     mosh:   88.5/ 102.0 ms              154.9 ms /  154.9 ms
```

Takeaways from this run:
- Display: mish trails mosh by ~3 ms on a LAN, and the gap closes as the link
  degrades (they're even on LOSSY) — consistent with QUIC vs UDP/OCB framing.
- Keyboard with prediction *off*, mish's echo round-trip is meaningfully
  slower than mosh's on good links (27.9 vs 12.7 ms LAN) — a real difference in
  the server→client echo path, worth a closer look.
- Predictive echo: mish is strong and stable (~2.2 ms across all conditions);
  mosh's adaptive prediction engages inconsistently at higher RTT.

These are a starting point for tuning, not a fixed verdict.
