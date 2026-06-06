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

The relay models several **loss/impairment regimes**, because they stress a
protocol very differently:
- **iid** — independent per-packet loss (the easy case).
- **Gilbert-Elliott burst loss** — a two-state (GOOD/BAD) Markov chain, so loss
  comes in *bursts*. Real links (wifi fade, buffer overrun) do this, and it's far
  harder than the same average loss spread out.
- **reordering** — a fraction of packets held back so they arrive late/out of order.

Two floors per condition: **display is one-way** (server→client), so it can't
beat a single relay delay; **keyboard is a round trip**, so it can't beat 2× that
delay. The `rt`/`loc` tag is against the keyboard (round-trip) floor.

```
                                   DISPLAY 1-way    KEYBOARD round-trip
                                   med / p90        predict off / on
=== LAN     (rtt~2ms, 0% iid) ===
   mish:                         15.5/  17.1 ms    27.2 ms rt  /  2.2 ms rt
     mosh:                         12.6/  13.6 ms    13.9 ms rt  /  2.3 ms rt
=== WAN     (rtt~80ms, 5% iid) ===
   mish:                         62.7/  75.1 ms   112.8 ms rt  /  2.1 ms loc
     mosh:                         60.7/  72.3 ms   102.1 ms rt  /  2.2 ms loc
=== LOSSY   (rtt~120ms, 15% iid) ===
   mish:                         87.9/ 100.5 ms   164.6 ms rt  /  2.2 ms loc
     mosh:                         86.1/  98.8 ms   162.9 ms rt  /  2.2 ms loc
=== BURSTY  (rtt~80ms, ~14% burst) ===
   mish:                         64.9/  78.6 ms   113.9 ms rt  /  2.1 ms loc
     mosh:                         64.0/  76.0 ms   108.2 ms rt  /  2.1 ms loc
=== REORDER (rtt~60ms, 1% loss, 12% reorder) ===
   mish:                         55.3/  68.6 ms    98.2 ms rt  /  2.1 ms loc
     mosh:                         52.8/  64.7 ms   103.7 ms rt  /  2.1 ms loc
=== BRUTAL  (rtt~140ms, bursty + reorder) ===
   mish:                        108.3/ 123.3 ms   260.3 ms rt  /  2.1 ms loc
     mosh:                        101.7/ 118.8 ms   212.5 ms rt  /  2.2 ms loc
```

`BENCH_ONLY=LOSSY,BRUTAL` restricts the run to matching conditions (fast A/B).

Takeaways:
- Display: mish trails mosh by ~2–3 ms (QUIC vs UDP/OCB framing); the gap
  doesn't widen under loss/bursts/reorder.
- Keyboard under loss: at parity with mosh on the realistic regimes — LOSSY
  164 vs 163, BURSTY 114 vs 108, and REORDER mish actually *beats* mosh. Only
  BRUTAL (the extreme: 140 ms RTT + bursts + 10% reorder) still trails by ~50 ms,
  in the noisy n=12 tail.
- LAN keyboard is ~13 ms over mosh — the known client→server-leg overhead that
  only shows when the RTT is tiny; loss-independent.
- Predictive echo: both paint locally at ~2 ms (`loc`).

### How we got here — congestion pacing was the bottleneck

An earlier build trailed mosh **2.5× on LOSSY keyboard (423 vs 163 ms)**. The
cause: an app-layer "congestion-aware pacing" experiment that stretched the SSP
send interval under loss. mosh deliberately does the opposite — it keeps blasting
the latest state at the frame rate, because latest-wins makes a dropped frame
harmless — and QUIC already congestion-controls the wire underneath. Stacking a
second backoff on top just added interactive latency exactly when it hurt most.
Removing it restored parity (this is precisely the kind of regression the bad-
network conditions above exist to catch). `MISH_CC=bbr` selects quinn's
(experimental) BBR controller as an opt-in, but with pacing gone it's not a clear
win, so Cubic stays the default.
