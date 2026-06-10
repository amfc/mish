# Performance: QUIC vs. upstream mosh

How mish uses QUIC, how that differs from upstream mosh's hand-rolled UDP, and
how the two compare under real network conditions, with the methodology and the
measured numbers. For the security model see [`security.md`](security.md); for
how things are tested see [`testing.md`](testing.md); the bench harness itself is
documented in `crates/bench-harness/README.md`.

## Summary

mish runs mosh's exact protocol (latest-wins state sync, predictive echo) on top
of QUIC unreliable datagrams instead of mosh's custom UDP+OCB. Measured against
upstream `mosh` through the same fault-injecting network, it is at parity across
realistic conditions, including heavy and bursty loss, with a steady 2 to 3 ms
framing overhead and one small, noisy, worst-case-only gap that we instrumented
and traced to a cause that is not the transport.

The question is not whether QUIC is fast. It is whether putting mosh's
loss-tolerant protocol on top of a full transport (with its own congestion
control and acknowledgements) costs anything mosh's bare UDP avoids. After
measuring, the answer is essentially no.

## The split: what QUIC does vs. what the protocol does

mish draws a clean line between the transport and the screen sync.

QUIC owns the wire. It provides the things mosh hand-rolls:

- crypto: per-session mutual TLS (the input-injection defense; see
  [`security.md`](security.md)), versus mosh's hand-rolled AES-OCB;
- connection migration and roaming: the connection survives the client's IP or
  port changing (Wi-Fi to cellular, NAT rebind, laptop resume), the "mobile" in
  mobile shell;
- congestion control of the actual packets;
- a reliable side-channel (ordered QUIC streams) used only for scrollback history
  fetches, kept off the hot path.

The State Synchronization Protocol (SSP) owns the screen, riding QUIC's
unreliable datagrams. This is mosh's protocol, ported faithfully: latest-wins, no
retransmit queue. Each send diffs the current screen against the state we assume
the peer already has; a lost datagram means the next send re-diffs from further
back. Loss is absorbed at the application layer by re-diffing, never by
retransmitting a datagram. QUIC does not retransmit datagrams, and we do not want
it to.

The whole live screen is one `Screen` state synchronized server to client; the
client's keystrokes are a `UserStream` synchronized client to server. Both are
just data, and the protocol core is sans-IO and deterministic (see
[`testing.md`](testing.md)).

## One congestion controller, and it is QUIC's

This is the load-bearing design decision, and the one that took measuring to get
right.

QUIC, unlike mosh's raw UDP, congestion-controls its datagrams: they are subject
to the congestion window and the pacer. mosh does none of that. It blasts the
latest screen state at its frame rate regardless of loss, because latest-wins
makes a dropped frame harmless. So there is a real fork.

The rule mish settled on is: do not double up. QUIC already protects the network
at the packet layer, so the SSP layer does zero congestion control of its own.
Its cadence is purely latency-paced (about 2 frames per RTT, clamped to
`[20, 250] ms`), exactly like mosh. Under loss it keeps pushing the freshest state
at the frame rate rather than backing off.

An earlier version added app-layer "congestion-aware pacing" that stretched the
send interval when QUIC reported congestion. The bad-network harness showed it
made mish 2.5x slower than mosh on heavy-loss keyboard echo (423 vs. 163 ms):
app-layer backoff stacked on QUIC's transport backoff, the wrong move for an
interactive shell. It was removed, and parity returned. This is what the harness
exists to catch.

QUIC itself is then tuned to be light-touch and fast-reacting for a tiny,
latency-critical flow.

## The tuning, knob by knob

All transport config lives in `crates/mish-quic/src/config.rs`.

| knob | setting (default is quinn's) | why it helps |
| --- | --- | --- |
| **app-layer pacing** | **off** | keep blasting the latest state under loss, like mosh; do not add backoff on top of QUIC's |
| **`initial_rtt`** | 100 ms (quinn: 333 ms) | sizes the first PTO; a packet lost during handshake, reconnect, or first keystroke recovers about 3x faster |
| **`max_ack_delay`** | 5 ms (quinn: ~25 ms) | tighter RTT estimate and faster loss detection on the echo path |
| **datagram send buffer** | 64 KiB (quinn: 1 MiB) | on a stall, drop stale screen diffs instead of queueing a backlog that plays out late; anti-bufferbloat, which is what latest-wins wants |
| **prospective resend** | on (mosh's optimization) | when nearly free, anchor a diff on the acked state, so a single lost datagram recovers a round-trip sooner |
| **per-instruction deflate** | on, for payloads > 64 B | terminal diffs are redundant; smaller datagrams mean fewer fragments and less loss exposure (tiny keystrokes and acks skip it) |
| **keepalive / idle** | 5 s / 60 s | keep the link warm and NAT bindings alive across naps and roaming |
| **congestion controller** | Cubic (BBR opt-in via `MISH_CC=bbr`) | Cubic is fine once pacing is gone; BBR (no cwnd collapse on loss) was A/B'd and did not narrow the worst-case tail (see Residual), so Cubic stays default and the opt-in remains as an escape hatch |

What mish deliberately does not do, in line with mosh: no datagram
retransmission, no ordering or reliability on the screen path, no app-layer
congestion backoff. The screen path is intentionally lossy-and-latest-wins.

## How it is measured

There is a real A/B harness (`crates/bench-harness`). It drives mish and upstream
`mosh` through the same fault-injecting loopback UDP relay, so QUIC and UDP/OCB
see identical impairment, and it measures both identically.

- **Display latency**, one-way server to client: a child paints a wall-clock
  marker, read off the client's reconstructed screen.
- **Keyboard latency**, round-trip echo: type a character, time until that glyph
  paints at the cursor cell. Each number is tagged against the round-trip floor
  (2x one-way delay): `rt` is a real server echo, `loc` is painted locally before
  any echo could arrive (predictive echo).

The relay models the loss regimes that stress a protocol differently: iid
(independent per-packet loss, the easy case), Gilbert-Elliott burst loss (a
two-state Markov chain; real links lose in bursts), and reordering. Numbers are
wall-clock medians and p90, machine-dependent. Read the mish-vs-mosh gap, not the
absolute values.

## Results

Representative release-build run (loopback). `rt` is real round-trip, `loc` is
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

† BRUTAL keyboard is the 300-sample median (15 loss realizations); a single
12-to-20-sample run is too noisy to be representative. See Residual below for the
full distribution. The difference is in the tail, not the median.

Reading it:

- **Display:** mish trails by 2 to 3 ms (QUIC's per-packet framing over bare
  UDP), and the gap does not widen under loss, bursts, or reordering.
- **Keyboard under loss:** at parity on the realistic regimes. LOSSY 165 vs. 163,
  BURSTY 114 vs. 108, and on REORDER mish beats mosh. On a LAN it is about 13 ms
  over mosh, a client-to-server-leg overhead that shows only when the RTT is tiny,
  and is loss-independent. Only BRUTAL (the synthetic worst case: 140 ms RTT plus
  bursts plus 10% reorder) still trails, by a noisy 30 to 50 ms; see below.
- **Predictive echo:** both paint locally at about 2 ms. Equivalent.

### A note on predictive echo

The keyboard "off / on" columns are predictive echo off versus on, mosh's
signature feature. With it on, the client paints what it predicts the server will
echo immediately (about 2 ms), then reconciles when the real echo arrives, so
typing feels instant regardless of the link. The mosh paper reports prediction is
correct for about 70% of keystrokes. The round-trip ("off") number is what the
unpredicted minority, and the moment after you press Enter, actually feel, and it
is where the network shows through. mish and mosh predict equally well, so the
comparison that matters is the round-trip column.

To see the paper's keystroke-response-time CDF for your own typing, run the
client with `--perf-log PATH` over a real link. It records, from inside the
client, the keypress-to-display latency of every keystroke (predicted echo near 0
ms, unpredicted near the round-trip), and `perf/perf-latency-graph.py` renders
the CDF in the style of the mosh paper's Figure 2 with its mosh and SSH curves
overlaid. See `perf/README.md`.

## Residual: the one gap, and why it is not what it looks like

Under BRUTAL (140 ms RTT plus bursts plus 10% reorder), keyboard-off looked like
it trailed by 30 to 50 ms in the short runs. Measured properly (300 round-trip
samples per client across 15 loss realizations), the gap is narrower and far more
specific than those 12-sample medians suggested:

| BRUTAL keyboard-off | mish | mosh |
| --- | --- | --- |
| **median** | **200 ms** | **194 ms** |
| per-seed-median average | 203 ms (sd 10) | 205 ms (sd 24) |
| mean | 301 ms | 253 ms |
| p90 | 590 ms | 324 ms |

The median is at parity: typical typing under this pathological link feels the
same on both, and mish is actually more consistent across loss realizations
(per-seed-median sd 10 vs. 24). The difference lives entirely in the tail. mish's
worst roughly 10% of keystrokes (deep inside a loss burst) take longer to
recover, which fattens the p90 and pulls the mean up about 47 ms. The earlier "30
to 50 ms gap" was exactly this tail leaking into noisy 12-sample medians.

So the question narrows to why a fatter tail, not a median shift. The transport
was instrumented three independent ways:

1. **Send-path hold:** stamp each datagram at the `send_datagram` call and read it
   at the receiver. Does QUIC sit on our packets when the window collapses? No.
   Transit is at wire speed even under BRUTAL (relay delay plus about 1.5 ms
   flat); 98% of packets arrive within the relay's own worst-case impairment.
2. **Loss amplification:** count datagrams the protocol asked to send versus
   datagrams that arrived, against the relay's own drop rate. Does QUIC drop our
   resends on top of the link's loss? No; delivered/sent matches the relay's
   survival within sampling noise (for example 80% vs. 83%).
3. **RTT inflation:** does QUIC's overhead inflate the protocol's RTT estimate and
   stretch the resend interval? Only by about 3 ms. Negligible.

So the tail is not a transport deficiency. QUIC moves our packets at wire speed
and loses them at exactly the rate the link imposes: no extra holding, no extra
drops, no RTT penalty. In the typical case mish is at parity; only in the deepest
bursts does QUIC's per-packet ack and recovery machinery cost a little more than
mosh's blast-everything UDP, stretching the worst ~10% of keystrokes.

We tested the most fixable suspect directly. The prime hypothesis was Cubic's
multiplicative cwnd collapse on loss (back off the window in a burst, throttle the
next keystrokes). QUIC's BBR controller does not collapse cwnd on loss, so it is a
clean A/B: if cwnd collapse fattens the tail, BBR flattens it. Re-running the
300-sample BRUTAL keyboard-off A/B with `MISH_CC=bbr` against the Cubic baseline,
with the mosh row as a cross-run anchor (mosh ignores `MISH_CC`, so it calibrates
how comparable the two sessions' conditions were):

| BRUTAL kbd-off p90 | Cubic | BBR |
| --- | --- | --- |
| mish | 645.8 ms | 715.6 ms |
| mosh (anchor) | 327.3 ms | 357.0 ms |
| **mish / mosh ratio** | **1.97x** | **2.00x** |

The anchor-normalized ratio is unchanged. The absolute rise in the BBR column is
entirely the BBR session running about 9% hotter (the mosh anchor rose in
lockstep), and the per-seed-median spread did not tighten either (sd 23.7 to
23.6). BBR does not narrow the tail, which rules out cwnd collapse as the cause
and is why Cubic stays the default.

### Pinning the tail: it is the SSP core's retry timing, not quinn

With the transport probes and the BBR A/B all pointing away from quinn, the cause
was pinned with a deterministic, quinn-free probe (`mish-ssp`'s
`examples/tail_probe.rs`): two bare `SspCore`s exchanging keystroke-to-echo round
trips over a virtual-time link whose loss, delay, and reorder model is copied
byte-for-byte from the bench relay. Same BRUTAL impairment, zero QUIC. The
protocol alone reproduces the tail:

| BRUTAL kbd-off (15x200 samples) | median | p90 |
| --- | --- | --- |
| sim, SSP core only, **no quinn** | 188 ms | **568 ms** |
| mish real (core + quinn) | 201 ms | 646 ms |
| mosh real | 195 ms | 327 ms |

The core by itself produces a 568 ms p90; quinn adds only the remaining ~80 ms
(the per-packet framing the three transport probes already measured). So the tail
is in the State Synchronization Protocol, not the transport. Bisecting it in the
sim isolates the mechanism:

- **Send cadence is not it.** Forcing the data-frame interval from `[20,250]` down
  to a flat 20 ms changed the p90 by noise (568 to 561). The latency-paced
  re-diff cadence is not what gates recovery.
- **`prospective_resend` is not it** (568 to 567 with it off).
- **The retransmission timeout (RTO) is.** Capping `rto` 1000 to 200 ms cut the
  p90 to 484 with no median cost; the live stack agreed, `MISH_SSP_RTO=250` moved
  the real mish p90 645.8 to 551.6 (anchored ratio 1.97 to 1.60), median
  unchanged.

The reason cadence is irrelevant and RTO dominates is in `calculate_timers`:
after every (re)send, `update_assumed_receiver_state` immediately re-grants the
just-sent state benefit of the doubt, so `current == assumed` and the sender
drops into the "unacked but assumed-delivered, wait a full `timeout()`" branch.
Each retry therefore waits a whole RTO plus `ack_delay`, never the frame interval.
Under BRUTAL the +80 ms reordered packets inflate `rttvar`, ballooning `RTO =
srtt + 4·rttvar` (removing just the reorder drops the sim p90 568 to 481), and a
keystroke caught in a deep burst eats several of those RTO-spaced retries.

mosh, running the same protocol but its own C++ implementation, tails about 240
ms thinner at p90, so this is a recovery-timing divergence from mosh in our port,
not a cost inherent to QUIC.

### Two candidate fixes, and what the live bench said

The mechanism suggests two levers. The probe and the live bench disagree about
which one actually works, a useful lesson in not trusting a synthetic-burst sim
past the thing it was validated on.

**(a) Retry faster after loss (`ResendMode`).** Re-poke at the frame interval
during the unacked window instead of waiting a full RTO. In the sim this is
dramatic: flat frame-rate retries collapse the p90 568 to 366 and cut the spread
3x (sd 296 to 100). A loss-gated variant (`FrameRateOnLoss`: stay optimistic for
one RTO, escalate to frame-rate only once loss is confirmed) was added to keep the
no-loss median; in the sim it lands at p90 399 / median 250. But on the live stack
it did essentially nothing: `MISH_SSP_RESEND=frame_on_loss` left the BRUTAL p90 at
an anchored 1.91x (vs. the 1.97x baseline, noise). The reason is burst depth: the
sim's synthetic Gilbert bursts drop several packets in a row, so a faster 2nd or
3rd retry helps; real BRUTAL tail keystrokes mostly need a single retransmit, so
there are no later retries to speed up. The cost is the first-detection RTO. The
modes stay as `ResendMode` knobs (default `Rto`, unchanged) but are not the fix.

**(b) Shrink the first-detection RTO. This is the one that works.** Capping the
RTO attacks detection latency directly, and BRUTAL inflates that RTO precisely
because the +80 ms reordered acks pump `rttvar` into `srtt + 4·rttvar`. Validated
on the live stack (`MISH_SSP_RTO`, mosh row as cross-run anchor),
median-preserving throughout:

| BRUTAL kbd-off (live) | mish p90 | mish median | mish / mosh p90 |
| --- | --- | --- | --- |
| RTO = 1000 (default) | 645.8 ms | 201.2 ms | **1.97x** |
| RTO = 250 | 551.6 ms | 200.8 ms | 1.60x |
| RTO = 180 | 483.3 ms | 201.9 ms | **1.37x** |

The tail shrinks from 1.97x to 1.37x of mosh with the median pinned at about 201
ms. (The sim agreed on direction, `rto` 1000 to 200 cut its p90 568 to 484, and on
the floor: a too-low `rto`=100 wrecks the median, 188 to 256, from spurious early
retransmits.)

### The shipped fix: derive the RTO from the transport's base RTT

An absolute RTO cap cannot be the default. 180 ms sits below the RTT on a
genuinely slow link and would cause constant spurious retransmits. The robust form
is to make the RTO track the path's base RTT rather than a reorder-inflated
estimate. That is exactly what mosh does: its `Connection` (network.cc) stamps
every packet with a monotonic `seq` and excludes out-of-order packets from the RTT
estimator (`if p.seq < expected_receiver_seq { return p.payload; }`, so the
payload still feeds state sync but never the RTT), so BRUTAL's +80 ms reordered
acks never inflate its SRTT or RTTVAR. mosh's sender branch logic is otherwise
identical to ours (verified: it also waits a full `timeout()+ACK_DELAY` between
retransmits); the only reason its tail is thinner is that its RTO stays small.

We tried two robust ways to estimate that base RTT.

**First attempt, consume quinn's RTT.** mish is on QUIC, which already maintains a
reorder- and retransmit-robust RTT (RFC 9002), so we surfaced `Transport::rtt()`
and fed it to the core. A wrinkle the bench exposed: quinn's smoothed RTT is
itself inflated under BRUTAL (loss plus ack-delay), so `RTO = 2·srtt` gave no
improvement (anchored 1.95x). Tracking the minimum of quinn's reported RTT (an
estimate of base RTT, immune to that inflation) and setting `RTO = 1.5 · min_rtt`
worked (1.59x, median preserved). But quinn only exposes the smoothed RTT publicly
(`min_rtt` lives in `RttEstimator`/BBR internals and the maintainers will not
surface it), so we were taking the min of a smoothed value: noisy across runs, and
a standing dependency on a thin, grudging API.

**Shipped fix, our own seq plus internal `min_rtt`.** So we ported mosh's
mechanism: a monotonic per-packet `Instruction::seq` (protocol v2) and the same
reorder guard in `recv`. A packet whose `seq` is below the highest seen is
excluded from RTT sampling (its state is still applied; only timing is protected).
Two findings:

- **The seq guard alone did not move the tail** (2.05x, noise). The bench types
  one key at a time and waits for the echo, so packets in each direction are
  spaced about a round-trip apart; a +80 ms reorder almost never leapfrogs a
  packet sent about 200 ms later, so there are essentially no seq-inversions for
  the guard to filter. It does matter under packet streaming (fast typing, screen
  bursts), which this benchmark does not exercise.
- **The win is the clean internal `min_rtt`** the guard enables. We track the
  minimum of the (seq-guarded) RTT samples and set `RTO = 1.5 · min_rtt`. A
  minimum is naturally robust: loss, reorder, and jitter only ever add to a
  sample, never lower it, so it tracks the true base RTT without needing quinn at
  all.

| BRUTAL kbd-off (live, mosh-anchored) | mish p90 | median | mish / mosh p90 | per-seed sd |
| --- | --- | --- | --- | --- |
| baseline (`srtt + 4·rttvar`, no guard) | 645.8 ms | 201.2 ms | **1.97x** | 22.5 |
| seq-guard alone (still `srtt+4·rttvar`) | 666.9 ms | 201.7 ms | 2.05x (no help) | 16.8 |
| quinn **min** RTT x 1.5 | 546.2 ms | 200.6 ms | 1.59x | 18.0 |
| **seq-guard + internal min RTT x 1.5 (default)** | **529.9 ms** | **200.7 ms** | **1.58x** | 28.2 |

The shipped default cuts the BRUTAL tail from 1.97x to 1.58x of mosh with the
median pinned at about 201 ms, and unlike the quinn path is fully self-contained:
no dependency on the transport's RTT API. `RTO = rto_srtt_factor · min_rtt`
(default 1.5x) scales correctly on a slow link (large base RTT gives large RTO)
and needs no magic constant. `MISH_SSP_RTO_FACTOR` and an absolute cap
`MISH_SSP_RTO` remain for tuning, and `MISH_SSP_RTT_SRC=quinn` selects the
transport-RTT path for A/B. Because this lever lives in the internal estimator,
the deterministic sim now shows it too (BRUTAL p90 568 to 499), the first of these
RTT fixes that does.

It still does not fully reach mosh (1.58x, not 1.0x), and that residual is no
longer the RTO. It is two things QUIC imposes that mosh avoids: (1) the 2-to-3 ms
per-packet QUIC framing, which over a multi-round-trip burst recovery compounds
into the ~80 ms the sim attributes to the transport (protocol-only sim 568 vs.
real mish 646); and (2) mosh measures a marginally cleaner base RTT via its
dedicated Connection-layer seq than we recover from `min` of the app-layer
samples. In short: the recovery-timing divergence is closed; what is left is the
cost of riding a real transport, which predictive echo hides at about 2 ms
regardless.

The bottom line: across everything a real session encounters, including heavy and
bursty loss, mish matches mosh at the median, with a slightly heavier tail only
under a synthetic worst case that is demonstrably not the transport's fault. And
predictive echo paints every keystroke locally at about 2 ms regardless, so even
that tail is hidden in practice.

## Running it yourself

```sh
cargo build --release                              # build mish + bench-child
cargo run -p bench-harness --release --bin bench-harness
```

`mosh-server` and `mosh-client` must be on `PATH` for the comparison rows
(otherwise it runs mish only). `BENCH_ONLY=LOSSY,BRUTAL` restricts to a subset for
a fast A/B. Always benchmark a release build; a debug mish vs. the release system
`mosh` is an unfair comparison. See `crates/bench-harness/README.md` for the full
methodology, the floor/`rt`/`loc` tagging, and how the loss models are configured.

### Reproducing the tail investigation

The 300-sample BRUTAL keyboard distribution (mean, sd, p90, the `[stats]` lines)
and the SSP-timing A/B knobs:

```sh
# 300-sample (15 seeds x 20) BRUTAL keyboard-off distribution, both clients:
BENCH_ONLY=BRUTAL BENCH_KBD_ONLY=1 BENCH_SEEDS=15 BENCH_KSAMPLES=20 MISH_STATS=1 \
  cargo run -p bench-harness --release --bin bench-harness

# SSP recovery-timing levers (mosh ignores them, so its row stays a clean anchor):
MISH_SSP_RTO_FACTOR=1.5 ...   # RTO = factor · base(min) RTT, the shipped fix (default 1.5)
MISH_SSP_RTT_SRC=quinn  ...   # base RTT from quinn's min instead of our seq-guarded min (A/B)
MISH_SSP_RTO=180        ...   # hard cap on the RTO (ms); absolute, so unsafe as a default
MISH_SSP_RESEND=frame_on_loss ...  # loss-gated frame-rate retries; helps the sim, not the bench
MISH_CC=bbr             ...   # BBR congestion controller (ruled out above)

# Deterministic, quinn-free protocol probe (instant; isolates core from transport):
cargo run -p mish-ssp --release --example tail_probe -- BRUTAL   # COND in {WAN,LOSSY,BURSTY,REORDER,BRUTAL,BRUTAL_NOREORDER}
RESEND=rto|frame|frame_on_loss   RTO=<ms>   SEND_MIN=<ms>   PROSPECTIVE=0|1   ./target/release/examples/tail_probe BRUTAL

# Deterministic, quinn-in-the-loop probe (instant; the real QUIC stack over turmoil):
cargo run -p mish-quic --features turmoil --example turmoil_latency -- BRUTAL   # COND in {LAN,WAN,LOSSY,BURSTY,BRUTAL}
MISH_SSP_RTO_FACTOR=1.5  KEYS=300  cargo run -p mish-quic --features turmoil --example turmoil_latency -- BRUTAL
```

### Three harnesses, and what each one sees

The tail investigation surfaced a fidelity ladder. Each rung adds realism, and a
fix that moves one rung may not move another, so it pays to know which is which:

| harness | transport | clock | what it captures | what it misses |
| --- | --- | --- | --- | --- |
| `tail_probe` (mish-ssp) | none (sans-IO core) | virtual | the SSP protocol plus recovery timing, instantly and deterministically | QUIC entirely; reorder only bites when packets stream |
| `turmoil_latency` (mish-quic) | **real quinn** | turmoil (simulated) | QUIC framing, acks, RTT estimator, congestion control, deterministically and instantly | a real OS network stack and scheduler |
| `bench-harness` (mish-ssp) | real quinn + real `mosh` | wall-clock | the true A/B against upstream mosh through one relay | reproducibility; it is slow and noisy |

Two concrete cases this ladder explains. (1) The `frame_on_loss` retry change
helped `tail_probe` but not the bench: its synthetic bursts are deeper than what
quinn's real datagram pacing produces, so faster subsequent retries had nothing to
bite. (2) The seq guard moves neither `tail_probe` nor the bench's keyboard
number, because both type one key at a time and wait; packets never stream closely
enough to reorder, so the guard earns its keep under fast typing or screen bursts,
a workload none of these three exercises yet (a streaming mode is the obvious next
sim upgrade). The RTT/RTO fix, by contrast, shows on all three, which is why we
trust it. `turmoil_latency` exists so that QUIC-in-the-loop questions no longer
require the slow wall-clock bench: it resolves the RTO lever cleanly (BRUTAL p90
about 478 ms at `rto_factor=1.5` vs. about 908 ms at 5.0).
