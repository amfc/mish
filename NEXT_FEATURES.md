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

## 3. Port forwarding over QUIC streams — **done**

**Why.** `ssh -L`/`-R`-style forwarding — something **mosh cannot do at all**
(its UDP/OCB transport has no reliable multiplexed channel). QUIC streams make it
almost free, turning mish from "a shell" into "a shell + tunnel."

**What shipped.** `mish-client -L [bind:]port:host:hostport` and `-R …`
(repeatable, ssh syntax). Each forwarded TCP connection maps to one
**bidirectional QUIC stream**, multiplexed over the existing authenticated
connection ([`mish::forward`](crates/mish/src/forward.rs)). A framed
`StreamHello` tags every side-channel stream so one accept loop demultiplexes
scrollback history and forwarding; after the hello a data stream is a pure byte
relay (`copy_bidirectional`). `-L` and `-R` are symmetric — the side that
*accepts* a stream is the side that dials the target. Once the stream exists QUIC
handles reliability, ordering, flow control, and congestion per stream. See
[`docs/port-forwarding.md`](docs/port-forwarding.md).

**Reuse.** Built on the reliable side-channel, the mutual-auth connection (no new
crypto), and the bootstrap CLI patterns — exactly as planned.

**Security** (full model in [`SECURITY.md`](SECURITY.md#port-forwarding--l---r)):
**off until explicitly requested** per-forward; the authenticated peer is the
owner (honoring its forward request is not a privilege escalation, as with ssh's
`AllowTcpForwarding`); a server kill switch `--no-forward`; and — the one
genuinely new surface — the client dials **only the targets it configured** for
`-R`, so a hostile server can't reach arbitrary client-local addresses. Bounded
by the concurrent-stream cap + per-stream flow control. Covered by e2e tests over
real QUIC ([`port_forward.rs`](crates/mish/tests/port_forward.rs)).

**Deferred (future work).** A per-target allow/deny policy (`PermitOpen`/
`PermitListen`-style); `-D` SOCKS dynamic forwarding; UDP; and IPv6 *literals in
the spec string* (bind/dial resolve IPv6 fine — only the colon-splitting spec
parser is IPv4/hostname-only). None are core.

---

## Suggested sequencing

All three reuse the reliable side-channel (already shipped) and add no new crypto.

1. **Clipboard (large)** — smallest: the small OSC 52 version already ships, so
   this is just moving big blobs onto the existing stream.
2. **Multi-client attach** — builds on the shipped session registry; mostly a
   `Screen` fan-out + an input-merge policy.
3. **Port forwarding** — *done* (§3). Highest new value; the security model is
   gated as planned (off until requested, owner model, `--no-forward`, client
   dials only configured `-R` targets) with adversarial e2e tests.

Every one of these should land with the same testing discipline the project
already holds itself to (see [`TESTING.md`](TESTING.md)): deterministic-sim
coverage where it touches the protocol, fuzz/no-panic on any new wire format, and
an explicit threat-model note in [`SECURITY.md`](SECURITY.md) for clipboard and
port forwarding.
