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

Representative run (loopback, debug build; absolute numbers are machine- and
build-dependent — read the mish-vs-mosh *gap*, not the raw values):

```
=== LAN    (rtt~2ms,  0% loss) ===
  DISPLAY (server→client, predict off)   KEYBOARD echo (predict off / on)
   mish:   21.1/  23.3 ms               35.3 ms /    2.9 ms
     mosh:   13.4/  14.7 ms               25.4 ms /    3.3 ms

=== WAN    (rtt~80ms, 5% loss) ===
   mish:   67.7/  83.3 ms              117.1 ms /    2.9 ms
     mosh:   60.7/  71.9 ms               59.7 ms /   59.8 ms
```

Takeaways from this run:
- mish carries a consistent ~5–8 ms display-latency overhead vs mosh.
- mish's predictive echo is strong and stable (~3 ms keyboard across all
  conditions); mosh's adaptive prediction engages inconsistently at higher RTT.

These are a starting point for tuning, not a fixed verdict.
