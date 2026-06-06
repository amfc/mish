# Next features — beyond mosh parity

mish has reached functional parity with upstream mosh (see
[`PARITY_AUDIT.md`](PARITY_AUDIT.md), [`FUTURE_WORK.md`](FUTURE_WORK.md)) and
already ships several features that go *beyond* it. This document is the
**forward** roadmap: the remaining net-new capability that exploits the two
things our stack has and mosh's hand-rolled UDP/OCB transport does not — **QUIC
reliable streams** and **QUIC crypto/migration/resumption** — on top of the
existing **SSP state-sync substrate**.

These are deliberately *not* in `NOT_IMPLEMENTING.md` (legacy cruft we decline to
port) — this is capability mosh can't offer.

> **Already shipped (and removed from this list):** the enabling primitive — a
> reliable, ordered QUIC **control stream** alongside the loss-tolerant datagram
> screen — plus **server-side scrollback** with the client scroll UX, and
> **persistent sessions + reattach** (`--persist` / `--session NAME`, with roaming
> = the full "never lose your shell" story). Because the stream primitive is done
> and in use, the features below **reuse** it rather than introduce it. One idea
> that used to be here, app-layer *congestion-aware pacing*, was built, measured
> to **hurt** interactive latency under loss, and removed — see
> [`PERFORMANCE.md`](PERFORMANCE.md) and the "one congestion controller, and it's
> QUIC's" strategy.

The architectural split that makes all of this a natural fit, not a fight:
**datagrams for the live, loss-tolerant screen; reliable streams for bulk /
secondary side-channels** (history, large clipboard, forwarded connections), all
inside the *same* mutually-authenticated connection — so streams inherit the auth
model with no new surface (each handler still bounds memory and validates input,
reusing the `fuzz_hostile` discipline).

---

## 1. Multi-client attach (shared / pair session)

**Why.** Pair programming, teaching, "watch my terminal" — over the same
state-sync substrate, read-only or read-write. mosh can't do this.

**Design.** Builds directly on the **shipped session registry** (persistent
sessions + reattach): allow **N clients attached to one session**. The server
fans the `Screen` state out to every attached client (each is just another SSP
receiver of the same `Complete` state — the substrate is already one-to-many
friendly). Input is the asymmetric part: merge multiple clients' `UserStream`s
into the PTY, with a per-client **role** — read-only (input dropped) or read-write
(input forwarded). A simple policy (owner grants write; optional input locking to
avoid interleaved-keystroke chaos) keeps it sane. Predictive echo stays per-client
and local.

**Reuse.** Everything from persistence + reattach; `Screen` broadcast is natural
(the driver already `publish_remote`s to subscribers). Per-session it's mostly a
fan-out + an input-merge policy.

**Risks / unknowns.** Input-arbitration UX (who can type, how writers are
granted/revoked); per-client geometry (different terminal sizes → smallest-window
or per-client viewport); auth for additional clients (each needs its own minted
cert, or an owner-issued grant); resize storms. Keep v1 to **one read-write owner
+ read-only viewers** and expand later.

**Effort.** Medium — the registry it builds on already exists.

---

## 2. Real clipboard over a reliable stream (large payloads)

**Why.** We already sync **OSC 52** clipboard contents (`Screen::clipboard`,
latest-wins, datagram-carried) — that's the *small* version, and it works for
modest payloads. The *big* version sends arbitrary-size clipboard blobs reliably
without bloating the per-frame datagram diff.

**Design.** Keep small OSC 52 on the datagram path (already done, monotonic
latest-wins). For large payloads, move the blob to the **reliable side-channel**:
the datagram diff carries only a *clipboard-epoch marker*; the actual bytes
transfer reliably out-of-band and the client applies them when complete. Same
mechanism both directions (server→client paste targets, client→server if we ever
support it). Optional size cap + user consent (clipboard is a classic exfil
channel — keep it opt-in/bounded).

**Reuse.** Existing `clipboard` field + its directional round-trip tests; the
reliable side-channel framing (`mish_ssp::framing`).

**Risks / unknowns.** Size limits + consent policy (security); chunking/cancel if
a newer clipboard supersedes an in-flight one; base64 vs raw on the wire.

**Effort.** Small–medium (the small version already ships; this is the
large-payload upgrade riding the existing stream plumbing).

---

## 3. Port forwarding over QUIC streams

**Why.** `ssh -L`/`-R`-style forwarding — something **mosh cannot do at all**
(its UDP/OCB transport has no reliable multiplexed channel). QUIC streams make it
almost free, turning mish from "a shell" into "a shell + tunnel."

**Design.** Each forwarded TCP connection maps to one **bidirectional QUIC
stream**, multiplexed over the existing authenticated connection. A control
message (on the existing reliable side-channel) opens a forward: "`-L`
local:port → remote:host:port" or the reverse. The client listens locally, opens
a stream per accepted connection, and the server dials the target (and vice versa
for `-R`). Pure byte-shoveling once the stream exists — QUIC handles reliability,
ordering, flow control, and congestion per stream.

**Reuse.** The reliable side-channel, the mutual-auth connection (no new crypto),
CLI parsing patterns from the bootstrap / `--ssh` work.

**Risks / unknowns.** This is a **real security surface** — forwarding lets the
remote reach into the local network and vice versa. Must be **off by default**,
explicitly requested per-forward, and ideally policy-gated (allowed hosts/ports).
Resource limits (max streams/forwards), half-close semantics, IPv6, and CLI
ergonomics (`-L`/`-R`/`-D` SOCKS?). Treat the threat model as seriously as the
auth work in `SECURITY.md`.

**Effort.** Medium–large, mostly the security/policy + CLI, not the data path.

---

## Suggested sequencing

All three reuse the reliable side-channel (already shipped) and add no new crypto.

1. **Clipboard (large)** — smallest: the small OSC 52 version already ships, so
   this is just moving big blobs onto the existing stream.
2. **Multi-client attach** — builds on the shipped session registry; mostly a
   `Screen` fan-out + an input-merge policy.
3. **Port forwarding** — highest new value, but gate the security model carefully
   (it's the only one that opens a network surface); do the threat-model work and
   adversarial tests first.

Every one of these should land with the same testing discipline the project
already holds itself to (see [`TESTING.md`](TESTING.md)): deterministic-sim
coverage where it touches the protocol, fuzz/no-panic on any new wire format, and
an explicit threat-model note in [`SECURITY.md`](SECURITY.md) for clipboard and
port forwarding.
