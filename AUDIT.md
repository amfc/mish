# mish quality audit

A multi-agent audit of the mish (mish) codebase for security, performance,
networking/terminal-algorithm correctness, and complexity/redundancy issues.

**Method.** Eight specialized finder agents swept the codebase — three on
security (SSH bootstrap & credentials; QUIC/TLS/cert-pinning; untrusted terminal
output / port-forward / PTY), two on algorithm correctness (SSP core + RTT/timers
+ fragmentation; terminal diff / predictive echo / scrollback), two on
performance (protocol + transport hot paths; terminal render/diff hot paths), and
one on complexity/redundancy across all crates. **Every** candidate finding was
then handed to a separate adversarial verifier agent whose job was to *refute* it
against the real source (and the documented threat model in `SECURITY.md`).
Severities below are the post-verification values; several were downgraded when
the verifier found the impact was bounded, and five candidates were rejected
outright as false-positives.

**Result: 14 confirmed issues (1 high, 2 medium, 11 low), 5 rejected.**

Trust-model reminder (`SECURITY.md`): the SSH bootstrap channel is trusted; the
UDP/QUIC path is hostile (observe/drop/dupe/corrupt/replay/inject/spoof). The
priority is protecting a regular `mish-client` user.

---

## 🔴 High

### H1 — Unauthenticated QUIC handshake failure tears down a live `--persist`/`--shared` session (remote DoS)

- **Where:** `crates/mish/src/bin/mish-server.rs:463` (persist preempt arm) and
  `:555` (shared accept arm); root cause in `crates/mish-quic/src/transport.rs:171`
  (`accept` does `incoming.await?`).
- **What:** `quinn::Endpoint::accept()` yields an `Incoming` as soon as a QUIC
  Initial arrives — *before* the pinned-client-cert check. `transport::accept`
  then drives the handshake with `incoming.await?`, which returns `Err` whenever
  the mutual-TLS handshake fails. The server's persistent and shared session
  loops propagate that with `?` (`incoming.context(...)?`), so the error escapes
  the session loop and ends the session. An attacker who can send a QUIC Initial
  to the server's UDP port — **no mish credentials required**, any off-the-shelf
  QUIC client suffices — fails the handshake and thereby kills the owner's live
  shell (for `--shared`, the session for *all* attached clients).
- **Why the existing test misses it:** `wire_attacks.rs::server_survives_pre_handshake_junk_flood`
  sends raw garbage that quinn drops at the endpoint (it never becomes an
  `Incoming`), and the test harness uses tolerant `if let Ok(...)` where the
  production loops use `?`. That contrast is itself evidence the `?` is an
  oversight.
- **Fix:** Don't let a per-connection handshake error terminate the session loop.
  Accept in a loop that logs-and-skips a failed/unauthenticated handshake and only
  surfaces a fatal closed-endpoint error. (Implemented as `accept_authenticated`.)

---

## 🟠 Medium

### M1 — Full-repaint re-ring emits the entire accumulated BEL count, unbounded, to the client TTY

- **Where:** `crates/mish-terminal/src/display.rs:446` (`emit_modes`).
- **What:** `bell_count` is a monotonic, uncapped `u64` (incremented once per BEL,
  `emulator.rs`). On a full repaint `old` is the blank screen
  (`bell_count == 0`), so `beeps = new.bell_count.saturating_sub(0)` is the *whole*
  accumulated count, and the loop pushes that many `0x07` bytes into the frame.
  Worse, `Screen::apply_diff` reconstructs the reference screen via
  `new_frame(&blank, self, false)` on **every** incremental diff
  (`screen.rs:342`), so the client re-materializes the full accumulated count into
  a throwaway buffer on each frame even when the diff carries no new bells. Trusted
  but attacker-influenced content (a user viewing a log full of `\a`, or arbitrary
  output in a shared session) can drive `bell_count` into the hundreds of millions
  → a multi-hundred-MB allocation written to the client's real TTY. The inline
  comment calling this "bounded and rare" is wrong on both counts.
- **Fix:** Cap the BELs emitted per frame to a small constant. More than a couple
  of coalesced bells is imperceptible, and the value is cosmetic (the receiver
  re-counts BELs to reconstruct its own `bell_count`, which is never compared
  across the wire), so a cap round-trips harmlessly.

### M2 — Reassembly memory accounting rescans all buffered fragments on every push (O(N²) per multi-fragment instruction)

- **Where:** `crates/mish-ssp/src/frag.rs:162` (`Defragmenter::push` eviction loop
  calling `buffered_bytes()`).
- **What:** The eviction loop condition is
  `while self.in_progress.len() > self.max_in_progress || self.buffered_bytes() > MAX_REASSEMBLY_BYTES`.
  Because the entry count is normally far under `max_in_progress` (64), the `||`
  short-circuit does **not** save the common path: `buffered_bytes()` is evaluated
  on essentially every non-completing fragment push, and it walks every in-progress
  reassembly summing chunk-table lengths. A large repaint split into N fragments
  thus rescans the up-to-N already-buffered chunks on each of its N−1 intermediate
  pushes → O(N²) on the per-datagram recv hot path. Memory stays correctly bounded
  (this is CPU-only, hence medium not high), but a peer streaming high-`count`
  fragments can amplify victim CPU.
- **Fix:** Maintain a running `buffered` byte counter, updated on slot-fill and on
  entry removal, so the cap check is O(1).

---

## 🟡 Low (confirmed)

| ID | Where | Issue | Suggested fix |
|----|-------|-------|---------------|
| L1 | `mish-ssp/src/core.rs:466,803` | **Min-RTT never decays.** `internal/transport_min_rtt` is only ever `.min()`-lowered; after a sustained *upward* path-RTT shift (handoff/route change) the RTO stays pinned low → chronic premature retransmits + over-eager loss recovery. Diverges from mosh's self-correcting `srtt+4·rttvar`; QUIC CC limits real harm. | Sliding-window min (BBR/mosh-style), or floor the base at a fraction of `srtt`. |
| L2 | `mish-terminal/src/screen.rs:332` | **`cols==1` desync.** Server clamps geometry to ≥1 col but client `apply_diff` rejects `cols<2` and silently returns → permanent display desync on a 1-col session (degenerate; never happens in practice). | Clamp the emulator minimum to 2 cols. |
| L3 | `mish-terminal/src/predict.rs:582` | **`glitch_trigger` latch.** Can stay `>0` with no pending predictions (only a *quick* confirm cures it; `advance()` never lowers it when empty), keeping the Adaptive overlay `showing()==true` on a fast link until a future prediction. | Decay `glitch_trigger` toward 0 when the engine empties. |
| L4 | `mish-terminal/src/predict.rs:427` | **`displayed_cell` clones a full `Cell`** when two of three callers read only `.c`. | Add a borrowing `displayed_char` helper. |
| L5 | `mish-terminal/src/predict.rs:439` | **Quadratic mid-line-insert prediction:** O(cols²) per insert keystroke (Vec-scan `retain` + per-column clone). Bounded by width & human typing speed. | Index predictions by `(row,col)`. |
| L6 | `mish-terminal/src/predict.rs:632` | **`predicted_screen` full-grid clone per repaint.** Largely architecturally inherent (the clone becomes the next diff baseline); negligible at real sizes. | Overlay predictions during the diff instead of materializing a Screen (speculative). |
| L7 | `mish-ssp/src/core.rs:695` | **Double screen diff per send** in `attempt_prospective_resend`. Bounded (sends capped ~50/s, µs-scale) and an intentional port of mosh's prospective-resend optimization. | None required; documented. |
| L8 | `mish-ssp/src/core.rs:513` | **`calculate_timers` equality scans** (3 comparisons, called twice per tick). Vec `==` short-circuits and the dominant per-tick cost is already `diff_from`/`clone`; low value. | Optional num/dirty short-circuit. |
| L9 | `mish-quic/src/transport.rs:136` + `config.rs:199` | **Dead code:** `client_endpoint` / `client_config_trusting` (pre-mutual-auth scaffolding) have zero callers; not lint-flagged because publicly re-exported. | Delete both + the re-export. |
| L10 | `mish-terminal/src/screen.rs:144,272` | **`Screen::blank` vs `new_initial` duplication:** identical 14-field literal differing only in geometry; `alternate_scroll: true` is a drift hazard. | `fn new_initial() -> Self { Screen::blank(0, 0) }`. |
| L11 | `mosh/src/bootstrap.rs:455,506` | **Host-key diagnostic inaccuracy:** an absent/unreadable `known_hosts` is TOFU-*accepted*, not refused as the doc comment & error string claim; `NoHomeDir` is reported as "key changed". Fail-closed, so not a vuln, but the messaging masks a real MITM signal. | Split `KeyChanged` vs environment-error messages; correct the doc. |

---

## ✓ Rejected as false-positives

Refuted by the verifiers against the code / threat model:

1. *Builtin SSH TOFU-accepts unknown host keys* — documented intentional limitation
   in `SECURITY.md`/`FUTURE_WORK.md`; `--bootstrap=ssh` is the stricter choice.
2. *OSC 52 clipboard written to the real system clipboard with no opt-out* —
   verified gated, not the unconditional write claimed.
3. *xorshift64\* RNG copy-pasted across modules* — not the duplication claimed.
4. *Identical bincode encode/decode boilerplate on 4 wire types* — refuted.
5. *TLS signature-verification trait methods duplicated between the two verifiers* —
   refuted.

---

## Fixes applied in this branch

- **H1** — added `accept_authenticated` in `mish-server.rs` and routed all
  session-accept sites through it, so a failed/unauthenticated handshake is
  logged-and-skipped instead of tearing down the session.
- **M1** — capped per-frame BEL emission in `display.rs::emit_modes`.
- **M2** — replaced the O(N) `buffered_bytes()` rescan with an O(1) running counter
  in `frag.rs`.

The remaining low-severity items are left as documented follow-ups.
