# Scrollback

`mish` scrolls back through **mosh's own server-held history**: the mouse
wheel at the shell prompt, or the Shift-Arrow keys anywhere. Upstream mosh has
neither — it tells you to run `tmux`.

---

## Using scrollback

### Mouse wheel / trackpad — at the shell prompt

At the shell prompt, just **scroll with the wheel or a two-finger swipe** like
you would in any other program. `mish` captures the wheel there and drives its
server-side scrollback, so scrolling works in every terminal — including ones
(kitty) that would otherwise turn wheel notches into arrow keys on the
alternate screen the client runs in.

The trade-off: with mouse reporting on, click-drag text selection at the
prompt needs your terminal's override modifier (usually **Shift-drag**).

### Keyboard — the same history without a mouse

The keyboard path reaches the same server-side history:

| Key | Action |
|-----|--------|
| **Shift-↑ / Shift-↓** | Scroll mosh's history up / down one page |
| **Shift-PageUp / Shift-PageDown** | Same, for terminals/keyboards that have those keys |

When you scroll into mosh's history a blue indicator appears
(`scrollback ↑N (Shift-PgDn to return)`) and the window title shows
`scrollback`. The view is **anchored to the buffer**, so output arriving while
you're scrolled won't slide it out from under you.

Shift-Arrow is the recommended path on laptops without a PageUp key, and it
needs no mouse reporting or terminal configuration at all.

### Returning to the live screen

Press **any other key** (or scroll back down to the bottom). The live screen
keeps updating the whole time you're scrolled — you just don't see it until you
return.

### Inside full-screen apps (vim, less, htop, tmux…)

When a full-screen app is running, both the **wheel** and **Shift-Arrow** are
handed straight to the app, so its own scrolling and key bindings work normally.
`mish` only drives its scrollback at the shell prompt.

---

## Caveats

- **Inside a full-screen app, Shift-Arrow does not scroll mosh history** — it's
  passed to the app on purpose (so it can't clobber the app's bindings). Detach
  from the app first to use mosh scrollback.

- **History depth is bounded.** The server keeps roughly the last **10,000**
  lines of scrollback (the emulator's grid limit); older lines are dropped.

- A single history fetch returns at most **512 rows**
  ([`MAX_HISTORY_ROWS`](../crates/mish-terminal/src/history.rs)); the client
  pages through deeper history one screenful at a time.

---

## How it works

### Wheel capture at the prompt

`mish-client` runs in the local terminal's **alternate screen**, which has no
native scrollback to offer — and kitty unconditionally converts wheel notches
into arrow keys there (it does not implement DECSET 1007), which the shell
reads as command-history navigation. So when the remote is at the shell prompt
(primary screen, no mouse tracking) the client **forces SGR button reporting**
on the local terminal: wheel notches arrive as reports it routes to mosh's
scrollback, and alternate-scroll is pinned off for terminals that honor 1007.
Clicks and drags at the prompt are swallowed.

Apps that *do* enable mouse reporting keep their exact modes, and their reports
are forwarded verbatim. A remote **alt-screen app without mouse reporting**
(less, plain vim) keeps native handling: the terminal's alternate-scroll — or
the client's replication of it — feeds it arrow keys, so the app scrolls its
own content.

### mosh's own scrollback (Shift-Arrow)

The live screen rides loss-tolerant **unreliable QUIC datagrams** as usual.
History, by contrast, is fetched **on demand over a reliable QUIC side-channel**
(a bidirectional stream), so it never bloats the per-frame diff:

```
client ── HistoryRequest { top_above, count } ──▶ server
client ◀── HistoryResponse { history_size, cols, rows } ── server
```

- **Server** ([`scrollback.rs`](../crates/mish/src/scrollback.rs)): a task accepts
  side-channel streams and answers each from the shared emulator's scrollback
  ([`Emulator::history_lines`](../crates/mish-terminal/src/emulator.rs)), reading
  directly from the `alacritty-terminal` grid's history. Requests are clamped
  (count ≤ 512, offset ≤ available history) so a malformed/hostile request is
  bounded.

- **Client** ([`client.rs`](../crates/mish/src/client.rs)): the scroll position is
  anchored to a **fixed point in the buffer** — the viewport's top row measured
  as lines above the *oldest* retained line — not to the live edge. On each
  scroll it converts that anchor to the protocol's `top_above` against the
  *current* `history_size`, refetching once if the buffer grew or shrank since
  the last look. This is why output arriving while you're scrolled doesn't shift
  the view, and why scrolling up always advances one contiguous page through the
  content.

### Key routing

The keys are recognized by their xterm modifier encodings in the client's stdin
reader and turned into scroll events:

| Keys | Bytes | Behavior |
|------|-------|----------|
| Shift-↑ / Shift-↓ | `ESC [ 1 ; 2 A` / `ESC [ 1 ; 2 B` | App-aware: scroll at the prompt, pass through to a full-screen app |
| Shift-PageUp / Shift-PageDown | `ESC [ 5 ; 2 ~` / `ESC [ 6 ; 2 ~` | Always scroll a page |

### Where it's tested

- [`scroll_client.rs`](../crates/mish/tests/scroll_client.rs) — Shift-Up / wheel
  render history at the prompt.
- [`mouse_routing.rs`](../crates/mish/tests/mouse_routing.rs) — keys/reports pass
  through to full-screen apps; mouse forwarded when the app reads it.
- [`scrollback_anchor.rs`](../crates/mish/tests/scrollback_anchor.rs) — the view
  stays anchored when output arrives mid-scroll.
- [`scrollback_deep.rs`](../crates/mish/tests/scrollback_deep.rs) — 250 lines of
  output plus the command are all reachable.
- [`scrollback_e2e.rs`](../crates/mish/tests/scrollback_e2e.rs) — a deep history
  window fetched over real QUIC.
