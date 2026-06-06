# Scrollback

`mish` lets you scroll back through terminal history two ways: your
terminal's **native** scrolling (mouse wheel / trackpad), and **mosh's own**
server-held history (the Shift-Arrow keys). Upstream mosh has neither — it tells
you to run `tmux`.

---

## Using scrollback

### Mouse wheel / trackpad — your terminal's native scrollback

At the shell prompt, just **scroll with the wheel or a two-finger swipe** like
you would in any other program. `mish` does **not** capture the wheel, so your
terminal scrolls its own buffer, native click-drag text selection works, and you
don't have to change any terminal settings.

This is the easy, everyday path. It shows whatever your terminal has kept in its
scrollback — which is the output of the current session as it scrolled past.

> In iTerm2 this works best with a generous (or unlimited) scrollback configured;
> that's the terminal's setting, not mosh's.

### Keyboard — mosh's own server-side history

For history that your terminal *doesn't* have (see [Caveats](#caveats)), use:

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

- **Native (wheel) scrolling shows your *terminal's* buffer**, i.e. the output
  you've actually seen this session. It will **not** show:
  - output produced **before you connected**, or
  - output produced **while you were disconnected** and then re-synced on
    reattach (`--session NAME`).

  For those, use **Shift-↑/↓** — that reaches mosh's server-side history, which
  the terminal never rendered.

- **Native scrolling depends on your terminal saving alternate-screen lines.**
  Terminals with real scrollback (e.g. iTerm2 with a large/unlimited buffer) do;
  a barebones terminal may not. If wheel scrolling does nothing, fall back to
  Shift-↑/↓ — that always works.

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

### Native wheel scrolling

`mish-client` runs in the **alternate screen** and repaints it with mosh's
minimal-diff renderer ([`display.rs`](../crates/mish-terminal/src/display.rs)),
which emits real terminal **scroll** operations (index / scroll-region) as
output flows rather than full repaints. A terminal that saves alternate-screen
lines therefore accumulates a coherent copy of the session in its own scrollback,
and the wheel scrolls that.

Crucially, the client **does not force mouse reporting** when the remote app
isn't using the mouse. That's what keeps the wheel (and native text selection)
with the terminal instead of stealing it. The one thing it still pins at the
shell prompt is **alternate-scroll off**, so a wheel notch can't be turned into
arrow keys (which the shell would read as command-history navigation). Apps that
*do* enable mouse reporting keep their exact modes, and their reports are
forwarded verbatim.

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
