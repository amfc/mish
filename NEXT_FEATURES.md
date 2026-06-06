# Next features — beyond mosh parity

mish has reached functional parity with upstream mosh (see
[`PARITY_AUDIT.md`](PARITY_AUDIT.md), [`FUTURE_WORK.md`](FUTURE_WORK.md): the
correctness/security items and the prediction/CLI/PTY/shutdown polish are done).
This document is the **forward** roadmap: features that make mish *better than*
mosh, chosen to exploit the two things our stack has that mosh's hand-rolled
UDP/OCB transport does not — **QUIC reliable streams** and **QUIC
crypto/migration/resumption** — alongside the existing **SSP state-sync
substrate**.

These are deliberately *not* in `NOT_IMPLEMENTING.md`: that file is for legacy
cruft we decline to port. This is net-new capability.

> **Status (updated):** the enabling primitive (#0) and server-side scrollback
> with the client scroll UX (#1) are **implemented** — see the
> `feat(transport)`/`feat(scrollback)`/`feat(client)` commits, `mish-ssp::framing`,
> `mish-quic` side-channels, `mish-terminal::history`, `mish::scrollback`, and the
> client's Shift-PageUp/PageDown scroll mode. The remaining features (#2–#6)
> below are still proposals.

## The one enabling primitive: turn on a reliable QUIC stream

Today the QUIC connection is **datagram-only** — streams are explicitly disabled
(`mish-quic/src/config.rs`: `max_concurrent_bidi_streams(0)`,
`max_concurrent_uni_streams(0)`). Everything rides unreliable datagrams, which is
exactly right for the *live screen* (loss-tolerant latest-wins state sync).

But three of the features below want a **reliable, ordered, flow-controlled byte
channel for bulk/secondary data** — history, large clipboard payloads, forwarded
connections. QUIC already gives us that for free; we just have to allow streams
and add a tiny framing/mux layer. So **enabling one bidirectional control stream
(plus on-demand streams) is a shared prerequisite** for #1, #4 (full version),
and #6. The design principle stays intact: **datagrams for the live, loss-tolerant
screen; streams for reliable side-channels.** That split is the whole reason this
is a natural fit and not a fight against the architecture.

Concretely this means:
- Re-enable streams in the transport config and extend the `Transport` trait (or
  add a sibling trait) with `open_bi()` / `accept_bi()` returning a reliable
  byte channel. The in-memory and madsim transports get the same so it all stays
  sim-testable.
- A small length-prefixed message framing on the control stream, with a typed
  request/response enum (history fetch, clipboard blob, port-forward open, …).
  Keep it `serde`/`bincode` like the instruction codec so fuzzers extend cheaply.
- Security: streams are inside the **same mutually-authenticated** connection, so
  they inherit the auth model with no new surface — but each request handler must
  still bound memory and validate input (reuse the `fuzz_hostile` discipline).

---

## 1. Server-side scrollback the client can scroll into  ✅ done

**Why.** mosh's single biggest real-world complaint is *no scrollback* — you're
told to run tmux. Fixing it is a genuine leapfrog and a natural fit for our
split transport.

**Design.** Keep the live screen exactly as today on datagrams. The server's
emulator already owns history (alacritty's grid has a scrollback region). On the
client, entering "scroll mode" (Shift-PageUp, or — now implemented — the
**mouse wheel**) sends a **history request** over the reliable control stream:
"give me rows `[top-N, top)` as of grid epoch E". The server serializes those
rows (the same `Screen`/cell encoding, optionally deflate-compressed like
instructions) and streams them back reliably. The client renders a **history
overlay** above the live screen — analogous to the prediction overlay in
`predict.rs`: a viewport into server-held history that the live screen scrolls
back into, dismissed on any keystroke.

**Wheel routing (implemented).** The wheel is only mosh's at the shell prompt.
The client keeps SGR button reporting on (and alternate-scroll off) on the real
terminal *while the remote app isn't reading the mouse*, so the wheel arrives as
a report it can route instead of the terminal turning it into arrow keys (which
the shell would read as command-history navigation — the original "scrollback
doesn't work" bug). Routing, by the synced remote state: app reads the mouse
(`mouse_mode != 0`) → forward the report verbatim; else on the **alternate
screen** (`alt_screen`, carried in a new diff-header flag byte) → synthesize
arrow keys so a plain pager like `less` scrolls itself; else (primary screen) →
mosh scrollback. Cost, as with tmux: native click-drag selection at the prompt
needs the terminal's bypass modifier (Shift, or ⌥ on macOS). See
`mosh/tests/mouse_routing.rs` + `client::tests`.

**Reuse.** `Screen`/cell codec, the deflate path, the overlay-compositing idea
from `predict.rs`/`notification.rs`, alacritty's existing scrollback buffer.

**Risks / unknowns.** alacritty scrollback access + eviction policy (how much
history to retain, memory cap); reflow on resize (history rows have their own
width); epoch/invalidation when the screen scrolls under you mid-fetch; defining
the client UX (mode, keys, indicator). Wire-format versioning.

**Effort.** Medium-large. The stream plumbing is the bulk; the history slice +
overlay are each moderate. **Start here** — it forces the reliable-stream
primitive that #4/#6 reuse, and delivers the headline win.

---

## 2. Session persistence + reattach  ✅ done (opt-in)

> **Status:** implemented end-to-end. `mish-server --persist` keeps the PTY +
> emulator alive across disconnects and accepts **reattach** connections, each
> re-syncing the full current screen automatically (a fresh SSP session syncs
> from scratch) — including output produced while no client was attached
> (`mosh/tests/reattach.rs`). `--session NAME` adds a host-side **registry**
> (`mish::registry`, a `0600` user-only file) so a later `mish host --session
> NAME` finds the live daemon and **reattaches** by reprinting its connect line
> (`mosh/tests/session_reattach.rs`); the client passes `--session` through the
> bootstrap. Reattach reuses the session credentials (socket-free; see
> SECURITY.md). Opt-in; default is a fresh session. *Remaining (optional):* 0-RTT
> for instant reattach, and a daemon-socket variant for zero key at rest.


**Why.** mosh sessions die with the client process. A persistent server + reattach
(abduco/tmux style), *combined with roaming*, is the complete "never lose your
shell" story — strictly more than mosh offers.

**Design.** Decouple the PTY+emulator+`SspCore` session lifetime from any one
client connection. The server keeps the session alive (detached) when the client
goes away, and a later client **reattaches** by re-establishing the QUIC
connection and re-syncing `Screen` state from wherever the SSP left off (the
state-sync substrate already re-diffs from an arbitrary baseline, so a fresh
client just looks like a peer that's very far behind — no special path). The
reattach is gated by the same minted client cert (delivered over SSH bootstrap),
so only the authorized party can reattach. A session registry keyed by a session
id lets one server host multiple detached sessions.

**0-RTT angle.** This is the feature that *wants* QUIC **0-RTT** for instant
reattach. We deliberately keep early data **off** today
(`config.rs::early_data_is_off`, asserted by a test) because 0-RTT data is
replayable. Re-enabling it must be **gated safely**: 0-RTT only for an
idempotent, non-mutating reattach handshake (never for keystrokes), with replay
caps — and the existing `early_data_is_off` test becomes the canary that flips to
an explicit, scoped `early_data_is_bounded` test. Resumption tickets ride QUIC's
own machinery.

**Reuse.** SSP's baseline-agnostic re-diff, mutual-auth cert pinning, roaming
(QUIC migration already tested). Server `--detach` daemonization already exists.

**Risks / unknowns.** Session-registry lifecycle (idle GC, max sessions, the
SIGUSR1-conditional idle-shutdown from `FUTURE_WORK`); secure session-id +
ticket handling; the 0-RTT replay analysis (security-critical — do this one
carefully and write the adversarial tests first); interaction with utmp/process
ownership. PTY survives client loss already (server owns it), so the core is
closer than it looks.

**Effort.** Large (mostly the lifecycle + security analysis, not the data path).

---

## 3. Multi-client attach (shared / pair session)

**Why.** Pair programming, teaching, "watch my terminal" — over the same
state-sync substrate, read-only or read-write. mosh can't do this.

**Design.** Builds directly on #2's session registry: allow **N clients attached
to one session**. The server fans the `Screen` state out to every attached client
(each is just another SSP receiver of the same `Complete` state — the substrate is
already one-to-many friendly). Input is the asymmetric part: merge multiple
clients' `UserStream`s into the PTY, with a per-client **role** — read-only
(input dropped) or read-write (input forwarded). A simple policy (owner grants
write; optional input locking to avoid interleaved-keystroke chaos) keeps it
sane. Predictive echo stays per-client and local.

**Reuse.** Everything from #2; `Screen` broadcast is natural (the driver already
`publish_remote`s to subscribers). Per-session it's mostly a fan-out + an
input-merge policy.

**Risks / unknowns.** Input-arbitration UX (who can type, how writers are
granted/revoked); per-client geometry (different terminal sizes → smallest-window
or per-client viewport); auth for additional clients (each needs its own minted
cert, or an owner-issued grant); resize storms. Keep v1 to **one read-write owner
+ read-only viewers** and expand later.

**Effort.** Medium *given #2*. Don't start before #2.

---

## 4. Real clipboard over a reliable stream

**Why.** We already sync **OSC 52** clipboard contents (`Screen::clipboard`,
latest-wins, datagram-carried) — that's the *small* version, and it works for
modest payloads. The *big* version sends arbitrary-size clipboard blobs reliably
without bloating the per-frame datagram diff.

**Design.** Keep small OSC 52 on the datagram path (already done, monotonic
latest-wins). For large payloads, move the blob to the **reliable control stream**:
the datagram diff carries only a *clipboard-epoch marker*; the actual bytes
transfer reliably out-of-band and the client applies them when complete. Same
mechanism both directions (server→client paste targets, client→server if we ever
support it). Optional size cap + user consent (clipboard is a classic exfil
channel — keep it opt-in/bounded).

**Reuse.** Existing `clipboard` field + its directional round-trip tests; the
reliable-stream framing from the enabling primitive.

**Risks / unknowns.** Size limits + consent policy (security); chunking/cancel if
a newer clipboard supersedes an in-flight one; base64 vs raw on the wire.

**Effort.** Small–medium (the small version already ships; this is the
large-payload upgrade riding #1's stream plumbing).

---

## 5. ~~Congestion-aware frame pacing (ECN → SSP send-interval)~~ — tried & removed

> **Resolved: don't do this.** It was built (feed QUIC's ECN-CE/loss congestion
> signal into the SSP send-interval, lengthening the frame interval under
> congestion) and then **removed**, because the A/B bad-network harness showed it
> made us **2.5× slower than mosh on heavy-loss keyboard echo (423 vs. 163 ms)**.
>
> The premise was wrong for an interactive shell. mosh deliberately does **no**
> congestion control on its datagrams — it keeps blasting the latest state at the
> frame rate, because latest-wins makes a dropped frame harmless — and QUIC
> already congestion-controls the wire underneath us. Stacking a second, app-layer
> backoff on top just added latency exactly when it hurt most. The settled
> strategy is **"one congestion controller, and it's QUIC's"**: SSP stays purely
> latency-paced like mosh. See **[`PERFORMANCE.md`](PERFORMANCE.md)** for the
> measurement, the per-knob transport tuning, and the proof we stay at parity
> under loss.

---

## 6. Port forwarding over QUIC streams

**Why.** `ssh -L`/`-R`-style forwarding — something **mosh cannot do at all**
(its UDP/OCB transport has no reliable multiplexed channel). QUIC streams make it
almost free, turning mish from "a shell" into "a shell + tunnel."

**Design.** Each forwarded TCP connection maps to one **bidirectional QUIC
stream**, multiplexed over the existing authenticated connection. A control
message (on the control stream from the enabling primitive) opens a forward:
"`-L` local:port → remote:host:port" or the reverse. The client listens locally,
opens a stream per accepted connection, and the server dials the target (and vice
versa for `-R`). Pure byte-shoveling once the stream exists — QUIC handles
reliability, ordering, flow control, and congestion per stream.

**Reuse.** The reliable-stream primitive (#0), the mutual-auth connection (no new
crypto), CLI parsing patterns from the `#37` work.

**Risks / unknowns.** This is a **real security surface** — forwarding lets the
remote reach into the local network and vice versa. Must be **off by default**,
explicitly requested per-forward, and ideally policy-gated (allowed hosts/ports).
Resource limits (max streams/forwards), half-close semantics, IPv6, and CLI
ergonomics (`-L`/`-R`/`-D` SOCKS?). Treat the threat model as seriously as the
auth work in `SECURITY.md`.

**Effort.** Medium–large, mostly the security/policy + CLI, not the data path.

---

## Suggested sequencing

```
        ┌─────────────────────────────┐
        │ #0 enable reliable stream    │  (shared primitive)
        └─────────────────────────────┘
           │            │            │
           ▼            ▼            ▼
   ┌──────────────┐  ┌──────────┐  ┌────────────────┐
   │ #1 scrollback│  │ #4 clip  │  │ #6 port-forward│
   │   (do first) │  │ (large)  │  │  (security!)   │
   └──────────────┘  └──────────┘  └────────────────┘

   ┌──────────────┐    ┌──────────────────────┐
   │ #2 persist + │ ─▶ │ #3 multi-client attach│
   │   reattach   │    │   (needs the registry)│
   └──────────────┘    └──────────────────────┘

   ┌──────────────────────────────┐
   │ #5 congestion-aware pacing    │  (independent — parallel track)
   └──────────────────────────────┘
```

1. **#1 Scrollback** — highest user value, and it forces the reliable-stream
   primitive (#0) that #4 and #6 then reuse cheaply. Start here.
2. **#5 Congestion pacing** — independent; run it as a parallel track in the
   SSP/transport layer while #1 lands.
3. **#4 Clipboard (large)** — small follow-on once the stream exists.
4. **#2 Persistence + reattach** — the security-heavy one (0-RTT analysis);
   sequence it deliberately and write the adversarial tests first.
5. **#3 Multi-client** — builds on #2's registry; cheap once that exists.
6. **#6 Port forwarding** — high value, but gate the security model carefully;
   can follow #1's stream work whenever there's appetite for the threat-model
   work.

Every one of these should land with the same testing discipline the project
already holds itself to (see [`TESTING.md`](TESTING.md)): deterministic-sim
coverage where it touches the protocol, fuzz/no-panic on any new wire format,
and an explicit threat-model note in [`SECURITY.md`](SECURITY.md) for #2/#4/#6.
