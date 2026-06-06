# bench-harness — mish vs mosh A/B latency harness

Drives **mish** and **upstream mosh** through the *same* fault-injecting
loopback UDP relay and measures both, identically, so the two are compared under
matched network impairment.

## What it measures

- **Display latency** (one-way, server→client): a child program (`bench-child`)
  paints a wall-clock marker every 30 ms; the harness reads it off the client's
  reconstructed screen and subtracts. Both processes share the machine clock.
- **Keyboard latency**: the harness types a character and times until **that exact
  glyph paints at the cursor cell** of the reconstructed screen. The server child
  is `cat`, whose PTY line discipline echoes input.

  It watches the destination cell for the typed character specifically — *not*
  "any screen content changed". That distinction matters: a client may move the
  cursor, repaint, or paint a prediction elsewhere faster than the network could
  ever deliver an echo, and an any-change detector would clock that as the
  "keyboard latency", producing samples below the physical round-trip floor. With
  prediction **off**, the glyph only appears once the server echo round-trips
  (≥ the link RTT); with prediction **on**, the client paints the predicted glyph
  locally first (well under the RTT). Each keyboard number is tagged against the
  round-trip floor (2×one-way delay): `rt` = a real echo round-trip, `loc` =
  painted locally before any echo could arrive. So the two columns are interpreted
  identically for both clients instead of conflating different events.

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

Two floors per condition: **display is one-way** (server→client), so it can't
beat a single relay delay; **keyboard is a round trip**, so it can't beat 2× that
delay. The `rt`/`loc` tag is against the keyboard (round-trip) floor.

```
                              DISPLAY 1-way     KEYBOARD round-trip
                              med / p90         predict off / on
=== LAN   (disp floor ~1 ms · kbd floor ~2 ms) ===
   mish:                    16.2/  17.9 ms    27.9 ms rt  /   2.1 ms rt
     mosh:                    12.5/  13.6 ms    12.9 ms rt  /   2.3 ms rt

=== DSL   (disp floor ~20 ms · kbd floor ~40 ms) ===
   mish:                    35.9/  38.6 ms    70.1 ms rt  /   2.1 ms loc
     mosh:                    33.2/  35.0 ms    56.0 ms rt  /   2.4 ms loc

=== WAN   (disp floor ~40 ms · kbd floor ~80 ms) ===
   mish:                    62.9/  75.5 ms   111.8 ms rt  /   2.2 ms loc
     mosh:                    60.5/  70.7 ms   102.6 ms rt  /   2.1 ms loc

=== LOSSY (disp floor ~60 ms · kbd floor ~120 ms) ===
   mish:                    89.1/ 103.3 ms   164.0 ms rt  /   2.1 ms loc
     mosh:                    83.7/  98.7 ms   152.1 ms rt  /   2.2 ms loc
```

(So e.g. WAN display at 60–75 ms is *not* below its floor: display's floor is the
~40 ms one-way delay, not the ~80 ms round-trip floor that governs keyboard.)

Takeaways from this run:
- Display: mish trails mosh by ~3 ms on a LAN, and the gap closes as the link
  degrades (even on LOSSY) — consistent with QUIC vs UDP/OCB framing.
- Keyboard, prediction off: every sample is a real round-trip (`rt`) for both, and
  the gap is modest and RTT-dominated at distance (WAN 111.8 vs 102.6, LOSSY 164
  vs 152). On a LAN, though, mish's round-trip (27.9 ms) is ~15 ms over mosh's
  (12.9 ms) despite near-identical displays — so mish's *client→server*
  keystroke leg carries extra latency (likely SSP send pacing) that only shows
  when the RTT is tiny. This is the one keyboard difference worth chasing.
- Predictive echo: both clients paint locally at ~2 ms (`loc`) across DSL/WAN/
  LOSSY — they are equivalent here. (At LAN the floor is ~2 ms, so even a local
  paint tags `rt`; prediction can't be distinguished from a round-trip when the
  RTT is already as fast as the prediction.)

Earlier versions of this harness compared "any screen change" and reported
mish winning prediction decisively while losing keyboard echo ~2× on WAN. Both
were artifacts of catching non-glyph changes below the round-trip floor; the
glyph+floor method above corrects them. These are a starting point for tuning,
not a fixed verdict.
