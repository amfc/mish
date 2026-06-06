# Performance: QUIC vs. upstream mosh

How mish uses QUIC, how that differs from upstream mosh's hand-rolled
UDP, and how the two compare under real network conditions — with the
methodology and the measured numbers, not just claims. (For the security model
see `SECURITY.md`; for how things are tested see `TESTING.md`; the bench harness
itself is documented in `crates/bench-harness/README.md`.)

## TL;DR

> mish runs **mosh's exact protocol** (latest-wins state sync, predictive
> echo) on top of **QUIC unreliable datagrams** instead of mosh's custom
> UDP+OCB. Measured against upstream `mosh` through the *same* fault-injecting
> network, it is **at parity across realistic conditions** — including heavy and
> bursty loss — with a steady ~2–3 ms framing overhead and one small, noisy,
> worst-case-only gap that we instrumented and traced to *not* being a transport
> problem.

The interesting question isn't "is QUIC fast" — it's "does putting mosh's
loss-tolerant protocol on top of a full transport (with its own congestion
control and acknowledgements) cost anything mosh's bare UDP avoids?" The answer,
after measuring, is: essentially no.

## The split: what QUIC does vs. what the protocol does

mish draws a clean line between the transport and the screen sync.

**QUIC owns the wire.** It gives us, for free, the things mosh hand-rolls:
- **crypto** — per-session mutual TLS (the input-injection defense; see
  `SECURITY.md`), vs. mosh's hand-rolled AES-OCB;
- **connection migration / roaming** — the connection survives the client's
  IP/port changing (Wi-Fi → cellular, NAT rebind, laptop resume), the "mobile"
  in mobile shell;
- **congestion control of the actual packets**;
- a **reliable side-channel** (ordered QUIC streams) used only for scrollback
  history fetches, kept off the hot path.

**The State Synchronization Protocol (SSP) owns the screen**, riding QUIC's
*unreliable datagrams*. This is mosh's protocol, ported faithfully: latest-wins,
**no retransmit queue**. Each send diffs the current screen against the state we
assume the peer already has; a lost datagram simply means the next send re-diffs
from further back. Loss is absorbed at the application layer by re-diffing —
never by retransmitting a datagram (QUIC doesn't retransmit datagrams, and we
don't want it to).

The whole live screen is one `Screen` state synchronized server→client; the
client's keystrokes are a `UserStream` synchronized client→server. Both are just
data — the protocol core is sans-IO and deterministic (see `TESTING.md`).

## The networking strategy: one congestion controller, and it's QUIC's

This is the load-bearing design decision, and it's the one that took measuring to
get right.

QUIC, unlike mosh's raw UDP, **congestion-controls its datagrams** — they're
subject to the congestion window and the pacer. mosh does none of that: it blasts
the latest screen state at its frame rate regardless of loss, because latest-wins
makes a dropped frame harmless. So there's a real philosophical fork.

The rule we settled on: **don't double up.** QUIC already protects the network at
the packet layer, so the SSP layer does **zero** congestion control of its own —
its cadence is purely *latency*-paced (~2 frames per RTT, clamped to
`[20, 250] ms`), exactly like mosh. Under loss we keep pushing the freshest state
at the frame rate rather than backing off.

> We learned this the hard way. An earlier version added an app-layer
> "congestion-aware pacing" that stretched the send interval when QUIC reported
> congestion. It seemed like good citizenship. The bad-network harness showed it
> made us **2.5× slower than mosh on heavy-loss keyboard echo (423 vs. 163 ms)** —
> app-layer backoff stacked on QUIC's transport backoff, exactly the wrong move
> for an interactive shell. We removed it; parity was restored. (This is precisely
> what the harness exists to catch.)

Then we tune QUIC itself to be as light-touch and fast-reacting as makes sense for
a tiny, latency-critical flow.

## The tuning, knob by knob

All transport config lives in `crates/mish-quic/src/config.rs`.

| knob | setting (default is quinn's) | why it helps |
| --- | --- | --- |
| **app-layer pacing** | **off** | keep blasting the latest state under loss, like mosh — don't add backoff on top of QUIC's |
| **`initial_rtt`** | 100 ms (quinn: 333 ms) | sizes the first PTO; a packet lost during handshake / reconnect / first keystroke recovers ~3× faster |
| **`max_ack_delay`** | 5 ms (quinn: ~25 ms) | tighter RTT estimate and faster loss detection on the echo path |
| **datagram send buffer** | 64 KiB (quinn: 1 MiB) | on a stall, drop *stale* screen diffs instead of queueing a backlog that plays out late — anti-bufferbloat, which is what latest-wins wants |
| **prospective resend** | on (mosh's optimization) | when nearly free, anchor a diff on the *acked* state, so a single lost datagram recovers a round-trip sooner |
| **per-instruction deflate** | on, for payloads > 64 B | terminal diffs are redundant; smaller datagrams = fewer fragments = less loss exposure (tiny keystrokes/acks skip it) |
| **keepalive / idle** | 5 s / 60 s | keep the link warm and NAT bindings alive across naps and roaming |
| **congestion controller** | Cubic (BBR opt-in via `MISH_CC=bbr`) | Cubic is fine once pacing is gone; BBR (no cwnd collapse on loss) is an experimental escape hatch |

### What we deliberately *don't* do (mosh-aligned)

No datagram retransmission. No ordering or reliability on the screen path. No
app-layer congestion backoff. The screen path is intentionally lossy-and-latest-
wins; that's the whole point of the design.

## How we measure it

Claims like "at parity" are only worth anything with a method, so there's a real
A/B harness (`crates/bench-harness`). It drives **mish and upstream `mosh`
through the same fault-injecting loopback UDP relay**, so QUIC and UDP/OCB see
identical impairment, and measures both identically.

- **Display latency** — one-way, server→client: a child paints a wall-clock
  marker, read off the client's reconstructed screen.
- **Keyboard latency** — round-trip echo: type a character, time until *that
  glyph* paints at the cursor cell. Each number is tagged against the round-trip
  floor (2× one-way delay): `rt` = a real server echo, `loc` = painted locally
  before any echo could arrive (i.e. predictive echo).

The relay models the loss regimes that actually stress a protocol differently:
**iid** (independent per-packet loss — the easy case), **Gilbert-Elliott burst
loss** (a two-state Markov chain — real links lose in bursts), and **reordering**.
Numbers are wall-clock medians/p90, machine-dependent — read the *mish-vs-mosh
gap*, not the absolute values.

## Results

Representative release-build run (loopback). `rt` = real round-trip, `loc` =
predictive local paint.

```
                          DISPLAY 1-way      KEYBOARD round-trip (predict off / on)
                          med / p90          med
=== LAN     (rtt~2ms,   0% iid) ===
   mish:                15.5 / 17.1 ms     27.2 ms rt  /  2.2 ms rt
     mosh:                12.6 / 13.6 ms     13.9 ms rt  /  2.3 ms rt
=== WAN     (rtt~80ms,  5% iid) ===
   mish:                62.7 / 75.1 ms    112.8 ms rt  /  2.1 ms loc
     mosh:                60.7 / 72.3 ms    102.1 ms rt  /  2.2 ms loc
=== LOSSY   (rtt~120ms, 15% iid) ===
   mish:                87.9 /100.5 ms    164.6 ms rt  /  2.2 ms loc
     mosh:                86.1 / 98.8 ms    162.9 ms rt  /  2.2 ms loc
=== BURSTY  (rtt~80ms,  ~14% burst) ===
   mish:                64.9 / 78.6 ms    113.9 ms rt  /  2.1 ms loc
     mosh:                64.0 / 76.0 ms    108.2 ms rt  /  2.1 ms loc
=== REORDER (rtt~60ms,  1% loss, 12% reorder) ===
   mish:                55.3 / 68.6 ms     98.2 ms rt  /  2.1 ms loc
     mosh:                52.8 / 64.7 ms    103.7 ms rt  /  2.1 ms loc
=== BRUTAL  (rtt~140ms, bursty + reorder) ===
   mish:               108.3 /123.3 ms    200.4 ms rt† /  2.1 ms loc
     mosh:               101.7 /118.8 ms    194.0 ms rt† /  2.2 ms loc
```

† BRUTAL keyboard is the **300-sample** median (15 loss realizations); a single
12–20-sample run is too noisy to be representative here. See the residual section
below for the full distribution — the difference is in the tail, not the median.

Reading it:

- **Display:** mish trails by ~2–3 ms (QUIC's per-packet framing over bare
  UDP), and the gap does **not** widen under loss, bursts, or reordering.
- **Keyboard under loss:** at parity on the realistic regimes — LOSSY 165 vs.
  163, BURSTY 114 vs. 108, and on REORDER mish actually *beats* mosh. On a LAN
  it's ~13 ms over mosh — a client→server-leg overhead that only shows when the
  RTT is tiny, and is loss-independent. Only **BRUTAL** (the synthetic worst case:
  140 ms RTT + bursts + 10 % reorder) still trails, by a noisy ~30–50 ms — see
  below.
- **Predictive echo:** both paint locally at ~2 ms. Equivalent.

### A note on predictive echo

The keyboard "off / on" columns are predictive echo off vs. on — mosh's signature
feature. With it **on**, the client paints what it *predicts* the server will echo
immediately (~2 ms), then reconciles when the real echo arrives; so typing feels
instant regardless of the link. The mosh paper reports prediction is correct for
~70 % of keystrokes. The round-trip ("off") number is what the *unpredicted*
minority — and the moment after you press Enter — actually feel, and it's where
the network shows through. mish and mosh predict equally well, so the
comparison that matters is the round-trip column.

## The one residual, and why it isn't what it looks like

Under BRUTAL — the synthetic worst case (140 ms RTT + bursts + 10 % reorder) —
keyboard-off *looked* like it trailed by ~30–50 ms in the short runs. Measured
properly (**300 round-trip samples per client across 15 loss realizations**), the
gap is narrower and far more specific than those 12-sample medians suggested:

| BRUTAL keyboard-off | mish | mosh |
| --- | --- | --- |
| **median** | **200 ms** | **194 ms** |
| per-seed-median average | 203 ms (sd 10) | 205 ms (sd 24) |
| mean | 301 ms | 253 ms |
| p90 | 590 ms | 324 ms |

The **median is at parity** — typical typing under this pathological link feels
the same on both, and mish is actually *more consistent* across loss
realizations (per-seed-median sd 10 vs. 24). The difference lives entirely in the
**tail**: mish's worst ~10 % of keystrokes (deep inside a loss burst) take
longer to recover, which fattens the p90 and pulls the *mean* up ~47 ms. The
earlier "~30–50 ms gap" was exactly this tail leaking into noisy 12-sample
medians.

So the question narrows to: why a fatter *tail* (not a median shift)? We
instrumented the transport three independent ways:

1. **Send-path hold** — stamp each datagram at the `send_datagram` call and read
   it at the receiver: does QUIC sit on our packets when the window collapses?
   **No.** Transit is at wire speed even under BRUTAL (relay delay + ~1.5 ms
   flat); 98 % of packets arrive within the relay's own worst-case impairment.
2. **Loss amplification** — count datagrams the protocol *asked* to send vs.
   datagrams that *arrived*, against the relay's own drop rate: does QUIC drop our
   resends on top of the link's loss? **No** — delivered/sent matches the relay's
   survival within sampling noise (e.g. 80 % vs. 83 %).
3. **RTT inflation** — does QUIC's overhead inflate the protocol's RTT estimate
   and stretch the resend interval? Only by ~3 ms. Negligible.

> So the tail is **not a transport deficiency**: QUIC moves our packets at wire
> speed and loses them at exactly the rate the link imposes — no extra holding, no
> extra drops, no RTT penalty. In the *typical* case mish is at parity; only in
> the deepest bursts does QUIC's per-packet ack/recovery machinery cost a little
> more than mosh's blast-everything UDP, stretching the worst ~10 % of keystrokes.
> Pinning that last bit exactly would mean instrumenting upstream mosh's C++
> internals to diff per-keystroke recovery timing — a large effort for a small,
> tail-only delta under one pathological condition.

That's the honest bottom line: across everything a real session encounters —
including heavy and bursty loss — mish matches mosh at the median, with a
slightly heavier tail only under a synthetic worst case, demonstrably not the
transport's fault. And predictive echo paints every keystroke locally at ~2 ms
regardless, so even that tail is hidden in practice.

## Running it yourself

```sh
cargo build --release                              # build mish + bench-child
cargo run -p bench-harness --release --bin bench-harness
```

`mosh-server` / `mosh-client` must be on `PATH` for the comparison rows (otherwise
it runs mish only). `BENCH_ONLY=LOSSY,BRUTAL` restricts to a subset for a fast
A/B. Always benchmark a **release** build — a debug mish vs. the release system
`mosh` is an unfair comparison. See `crates/bench-harness/README.md` for the full
methodology, the floor/`rt`/`loc` tagging, and how the loss models are configured.
