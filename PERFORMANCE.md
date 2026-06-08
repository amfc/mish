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
| **congestion controller** | Cubic (BBR opt-in via `MISH_CC=bbr`) | Cubic is fine once pacing is gone; BBR (no cwnd collapse on loss) was A/B'd and did **not** narrow the BRUTAL tail (see residual section), so Cubic stays default — the opt-in remains as an escape hatch |

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

We did, however, test the most fixable suspect directly. The prime hypothesis was
Cubic's multiplicative **cwnd collapse** on loss (back off the window in a burst,
throttle the next keystrokes). QUIC's BBR controller doesn't collapse cwnd on
loss, so it's a clean A/B: if cwnd collapse fattens the tail, BBR flattens it.
Re-running the 300-sample BRUTAL keyboard-off A/B with `MISH_CC=bbr` against the
Cubic baseline, with the **mosh row as a cross-run anchor** (mosh ignores
`MISH_CC`, so it calibrates how comparable the two sessions' conditions were):

| BRUTAL kbd-off p90 | Cubic | BBR |
| --- | --- | --- |
| mish | 645.8 ms | 715.6 ms |
| mosh (anchor) | 327.3 ms | 357.0 ms |
| **mish / mosh ratio** | **1.97×** | **2.00×** |

The anchor-normalized ratio is **unchanged** — the absolute rise in the BBR column
is entirely the BBR session running ~9 % hotter (the mosh anchor rose in lockstep),
and the per-seed-median spread didn't tighten either (sd 23.7 → 23.6). **BBR does
not narrow the tail**, which **rules out cwnd collapse** as the cause and is why
Cubic stays the default.

### Pinning the tail: it's the SSP core's retry timing, not quinn

With the transport probes and the BBR A/B all pointing *away* from quinn, we pinned
the cause directly with a **deterministic, quinn-free probe** (`mish-ssp`'s
`examples/tail_probe.rs`): two bare `SspCore`s exchanging keystroke→echo round trips
over a virtual-time link whose loss/delay/reorder model is copied byte-for-byte from
the bench relay. Same BRUTAL impairment, *zero* QUIC. The protocol alone reproduces
the tail:

| BRUTAL kbd-off (15×200 samples) | median | p90 |
| --- | --- | --- |
| sim — SSP core only, **no quinn** | 188 ms | **568 ms** |
| mish real (core + quinn) | 201 ms | 646 ms |
| mosh real | 195 ms | 327 ms |

The core *by itself* produces a 568 ms p90; quinn adds only the remaining ~80 ms
(the per-packet framing the three transport probes already measured). **So the tail
is in the State Synchronization Protocol, not the transport.** Bisecting it in the
sim isolates the mechanism cleanly:

- **Send cadence is not it.** Forcing the data-frame interval from `[20,250]` down
  to a flat 20 ms changed the p90 by noise (568 → 561). The latency-paced re-diff
  cadence is *not* what gates recovery.
- **`prospective_resend` is not it** (568 → 567 with it off).
- **The retransmission timeout (RTO) is.** Capping `rto` 1000 → 200 ms cut the p90
  to 484 with no median cost; the live stack agreed — `MISH_SSP_RTO=250` moved the
  real mish p90 645.8 → 551.6 (anchored ratio 1.97 → 1.60), median unchanged.

The reason cadence is irrelevant and RTO dominates is in `calculate_timers`: after
every (re)send, `update_assumed_receiver_state` immediately re-grants the
just-sent state benefit-of-the-doubt, so `current == assumed` and the sender drops
into the *"unacked but assumed-delivered → wait a full `timeout()`"* branch. **Each
retry therefore waits a whole RTO + `ack_delay`, never the frame interval.** Under
BRUTAL the +80 ms reordered packets inflate `rttvar`, ballooning
`RTO = srtt + 4·rttvar` (removing just the reorder drops the sim p90 568 → 481), and
a keystroke caught in a deep burst eats several of those RTO-spaced retries.

mosh — running the same protocol but its own C++ implementation — tails ~240 ms
thinner at p90, so this is a recovery-timing **divergence from mosh in our port**,
not a cost inherent to QUIC.

### Two candidate fixes, and what the live bench said about each

The mechanism suggests two levers. The probe and the live bench disagree about
which one actually works — a useful lesson in not trusting a synthetic-burst sim
past the thing it was validated on.

**(a) Retry faster after loss (`ResendMode`).** Re-poking at the frame interval
during the unacked window instead of waiting a full RTO. In the sim this is dramatic
— flat frame-rate retries collapse the p90 568 → 366 and cut the spread 3×
(sd 296 → 100). A loss-gated variant (`FrameRateOnLoss`: stay optimistic for one RTO,
escalate to frame-rate only once loss is confirmed) was added to try to keep the
no-loss median; in the sim it lands at p90 399 / median 250. **But on the live stack
it did essentially nothing:** `MISH_SSP_RESEND=frame_on_loss` left the BRUTAL p90
at an anchored 1.91× (vs the 1.97× baseline — noise). The reason is burst *depth*:
the sim's synthetic Gilbert bursts drop several packets in a row, so a faster 2nd/3rd
retry helps; real BRUTAL tail keystrokes mostly need a **single** retransmit, so
there are no later retries to speed up — the cost is the *first-detection* RTO. The
modes stay as `ResendMode` knobs (default `Rto`, unchanged) but are not the fix.

**(b) Shrink the first-detection RTO — this is the one that works.** Capping the RTO
attacks the detection latency directly, and BRUTAL inflates that RTO precisely
because the +80 ms reordered acks pump `rttvar` into `srtt + 4·rttvar`. Validated on
the live stack (`MISH_SSP_RTO`, mosh row as cross-run anchor), **median-preserving
throughout**:

| BRUTAL kbd-off (live) | mish p90 | mish median | mish / mosh p90 |
| --- | --- | --- | --- |
| RTO = 1000 (default) | 645.8 ms | 201.2 ms | **1.97×** |
| RTO = 250 | 551.6 ms | 200.8 ms | 1.60× |
| RTO = 180 | 483.3 ms | 201.9 ms | **1.37×** |

The tail shrinks from 1.97× → 1.37× of mosh with the median pinned at ~201 ms. (The
sim agreed on direction — `rto` 1000→200 cut its p90 568→484 — and on the floor: a
too-low `rto`=100 wrecks the median, 188→256, from spurious early retransmits.)

### The shipped fix: derive the RTO from the transport's *base* RTT

An absolute RTO cap can't be the default — 180 ms sits below the RTT on a genuinely
slow link and would cause constant spurious retransmits. The robust form is to make
the RTO track the path's *base* RTT rather than a reorder-inflated estimate. That's
exactly what **mosh** does: its `Connection` (network.cc) stamps every packet with a
monotonic `seq` and excludes out-of-order packets from the RTT estimator
(`if p.seq < expected_receiver_seq { return p.payload; }` — the payload still feeds
state sync, but never the RTT), so BRUTAL's +80 ms reordered acks never inflate its
`SRTT`/`RTTVAR`. Mosh's sender branch logic is otherwise identical to ours (verified:
it also waits a full `timeout()+ACK_DELAY` between retransmits) — the *only* reason
its tail is thinner is that its RTO stays small.

We tried two robust ways to estimate that base RTT.

**First attempt — consume quinn's RTT.** We're on QUIC, which already maintains a
reorder/retransmit-robust RTT (RFC 9002), so we surfaced `Transport::rtt()` and fed
it to the core. A wrinkle the bench exposed: quinn's *smoothed* RTT is itself
inflated under BRUTAL (loss + ack-delay), so `RTO = 2·srtt` gave no improvement
(anchored 1.95×). Tracking the **minimum** of quinn's reported RTT — an estimate of
the base RTT, immune to that inflation — and setting `RTO = 1.5 · min_rtt` worked
(1.59×, median preserved). But quinn only exposes the *smoothed* RTT publicly
(`min_rtt` lives in `RttEstimator`/BBR internals and the maintainers won't surface
it), so we were taking the min of a smoothed value — noisy across runs, and a
standing dependency on a thin, grudging API.

**Shipped fix — our own seq + internal `min_rtt`.** So we ported mosh's mechanism:
a monotonic per-packet `Instruction::seq` (protocol v2) and the same reorder guard
in `recv` — a packet whose `seq` is below the highest seen is excluded from RTT
sampling (its state is still applied; only timing is protected). Two findings:

- **The seq guard *alone* didn't move the tail** (2.05× — noise). The bench types
  one key at a time and waits for the echo, so packets in each direction are spaced
  ~a round-trip apart; a +80 ms reorder almost never leapfrogs a packet sent ~200 ms
  later, so there are essentially no seq-inversions for the guard to filter. (It
  *does* matter under packet streaming — fast typing, screen bursts — which this
  benchmark doesn't exercise; see "what the sim/bench miss" in the residual notes.)
- **The win is the clean internal `min_rtt`** the guard enables: we track the
  minimum of the (seq-guarded) RTT samples and set `RTO = 1.5 · min_rtt`. A minimum
  is naturally robust — loss, reorder, and jitter only ever *add* to a sample, never
  lower it — so it tracks the true base RTT without needing quinn at all.

| BRUTAL kbd-off (live, mosh-anchored) | mish p90 | median | mish / mosh p90 | per-seed sd |
| --- | --- | --- | --- | --- |
| baseline (`srtt + 4·rttvar`, no guard) | 645.8 ms | 201.2 ms | **1.97×** | 22.5 |
| seq-guard alone (still `srtt+4·rttvar`) | 666.9 ms | 201.7 ms | 2.05× (no help) | 16.8 |
| quinn **min** RTT × 1.5 | 546.2 ms | 200.6 ms | 1.59× | 18.0 |
| **seq-guard + internal min RTT × 1.5 (default)** | **529.9 ms** | **200.7 ms** | **1.58×** | 28.2 |

The shipped default cuts the BRUTAL tail 1.97× → 1.58× of mosh with the median
pinned at ~201 ms, and — unlike the quinn path — is **fully self-contained**: no
dependency on the transport's RTT API. `RTO = rto_srtt_factor · min_rtt` (default
1.5×) scales correctly on a slow link (large base RTT ⇒ large RTO) and needs no
magic constant; `MISH_SSP_RTO_FACTOR` and an absolute cap `MISH_SSP_RTO` remain
for tuning, and `MISH_SSP_RTT_SRC=quinn` selects the transport-RTT path for A/B.
Because this lever lives in the internal estimator, the **deterministic sim now
shows it too** (BRUTAL p90 568 → 499) — the first of these RTT fixes that does.

It still doesn't fully reach mosh (1.58×, not 1.0×), and that residual is *not* the
RTO anymore — it's two things QUIC imposes that mosh avoids: (1) the ~2–3 ms
per-packet QUIC framing, which over a multi-round-trip burst recovery compounds into
the ~80 ms the sim attributes to the transport (protocol-only sim 568 vs real
mish 646); and (2) mosh measures a marginally cleaner base RTT via its dedicated
Connection-layer seq than we recover from `min` of the app-layer samples. In short:
the *recovery-timing* divergence is closed; what's left is the cost of riding a real
transport, which predictive echo hides at ~2 ms regardless.

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

### Reproducing the tail investigation

The 300-sample BRUTAL keyboard distribution (mean/sd/p90, the `[stats]` lines) and
the SSP-timing A/B knobs:

```sh
# 300-sample (15 seeds × 20) BRUTAL keyboard-off distribution, both clients:
BENCH_ONLY=BRUTAL BENCH_KBD_ONLY=1 BENCH_SEEDS=15 BENCH_KSAMPLES=20 MISH_STATS=1 \
  cargo run -p bench-harness --release --bin bench-harness

# SSP recovery-timing levers (mosh ignores them, so its row stays a clean anchor):
MISH_SSP_RTO_FACTOR=1.5 ...   # RTO = factor · base(min) RTT — the shipped fix (default 1.5)
MISH_SSP_RTT_SRC=quinn  ...   # base RTT from quinn's min instead of our seq-guarded min (A/B)
MISH_SSP_RTO=180        ...   # hard cap on the RTO (ms); absolute, so unsafe as a default
MISH_SSP_RESEND=frame_on_loss ...  # loss-gated frame-rate retries — helps the sim, not the bench
MISH_CC=bbr             ...   # BBR congestion controller (ruled out above)

# Deterministic, quinn-free protocol probe (instant; isolates core from transport):
cargo run -p mish-ssp --release --example tail_probe -- BRUTAL   # COND ∈ {LAN-ish via WAN,LOSSY,BURSTY,REORDER,BRUTAL,BRUTAL_NOREORDER}
RESEND=rto|frame|frame_on_loss   RTO=<ms>   SEND_MIN=<ms>   PROSPECTIVE=0|1   ./target/release/examples/tail_probe BRUTAL

# Deterministic, quinn-IN-THE-LOOP probe (instant; the real QUIC stack over turmoil):
cargo run -p mish-quic --features turmoil --example turmoil_latency -- BRUTAL   # COND ∈ {LAN,WAN,LOSSY,BURSTY,BRUTAL}
MISH_SSP_RTO_FACTOR=1.5  KEYS=300  cargo run -p mish-quic --features turmoil --example turmoil_latency -- BRUTAL
```

### Three harnesses, and what each one sees

The tail investigation surfaced a fidelity ladder — each rung adds realism, and a
fix that moves one rung may not move another, so it pays to know which is which:

| harness | transport | clock | what it captures | what it misses |
| --- | --- | --- | --- | --- |
| `tail_probe` (mish-ssp) | none (sans-IO core) | virtual | the SSP protocol + recovery timing, instantly & deterministically | QUIC entirely; reorder only bites when packets stream |
| `turmoil_latency` (mish-quic) | **real quinn** | turmoil (simulated) | QUIC framing / acks / RTT estimator / congestion control, deterministically & instantly | a *real* OS network stack and scheduler |
| `bench-harness` (mish-ssp) | real quinn + real `mosh` | wall-clock | the true A/B against upstream mosh through one relay | reproducibility; it's slow and noisy |

Two concrete cases this ladder explains: (1) the **`frame_on_loss`** retry change
helped `tail_probe` but not the bench — its synthetic bursts are deeper than what
quinn's real datagram pacing produces, so faster *subsequent* retries had nothing to
bite. (2) The **seq guard** moves neither `tail_probe` nor the bench's
*keyboard* number, because both type one key at a time and wait — packets never
stream closely enough to reorder; the guard earns its keep under fast typing / screen
bursts, a workload none of these three exercises yet (a streaming mode is the obvious
next sim upgrade). The RTT/RTO fix, by contrast, shows on all three — which is why we
trust it. `turmoil_latency` exists so that QUIC-in-the-loop questions no longer
*require* the slow wall-clock bench: it resolves the RTO lever cleanly (BRUTAL p90
≈478 ms at `rto_factor=1.5` vs ≈908 ms at 5.0).
