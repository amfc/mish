# Future work

Remaining differences from upstream mosh, with rough effort. None are deep
protocol gaps — mostly extra terminal state to sync and a richer prediction
trigger. (Wire compatibility and zero-RTT are explicit non-goals — see README.)

## Terminal features not yet synced

The pattern for all of these is the same one already used for bracketed-paste /
mouse / cursor-style in `mish-terminal`: add a field to `Screen`, populate it in
`Emulator::snapshot` from `term.mode()` / a listener event, and emit the
escape on change in `display::new_frame` (+ a round-trip test). Difficulty is
relative to that established pattern.

- **Focus-event mode (DECSET 1004)** — *trivial.* Just another `TermMode` bit
  (`TermMode::FOCUS_IN_OUT`); add to the mode bitfield and emit `ESC[?1004h/l`.
  Identical to the mouse-mode handling already in place.
- **Alternate-scroll mode (1007)** — *trivial.* Same pattern
  (`TermMode::ALTERNATE_SCROLL`).
- **OSC 52 clipboard** — *moderate.* alacritty surfaces it as
  `Event::ClipboardStore(ClipboardType, String)`; capture the latest value in the
  `TitleListener` (rename it), add a `clipboard: Option<String>` to `Screen`, and
  emit `ESC]52;c;<base64>ST` on change. Needs base64 (we already hand-roll hex in
  `bootstrap.rs`; add base64 the same way). It's an event, not grid state, so
  decide "latest-wins" semantics like mosh does.
- **Icon name (OSC 1) / title stack (OSC 22/23)** — *low value / check support.*
  alacritty folds OSC 0/2 into one `Event::Title` and doesn't track icon name or
  a title stack separately, so this would need emulator-side work or is simply
  not representable. Probably skip.

## Prediction adaptiveness (mosh parity)

Today `PredictMode::Adaptive` gates display purely on SRTT
(`ADAPTIVE_SRTT_TRIGGER_MS`). mosh additionally builds confidence from a
*prediction track record* before showing predictions on a marginal link.

- **`CorrectNoCredit` accounting + confidence trigger** — *moderate.* In
  `predict.rs`, when culling a confirmed-correct prediction, distinguish "correct
  and changed the screen" (credit) from "matched what was already there"
  (no credit), and only enable the overlay once enough credited-correct
  predictions have accumulated (combined with the SRTT gate). Mirrors mosh's
  `OverlayManager` `srtt_trigger` + glitch hysteresis. Mechanics are otherwise
  already present (validation, flagging, glitch).

## Server ops plumbing (mish-server)

- **utmp/wtmp accounting, motd, setuid drop, locale validation** — *moderate,
  OS-specific.* Real session/login plumbing the daemon would do in production;
  orthogonal to the protocol.
- **SSH-bootstrapped real cert pinning** — *small.* The demo trusts the cert
  printed over SSH; production could pin it via known_hosts-style storage.

## Misc

- **Diff: full mosh scroll-region optimization** — we detect whole-screen
  scroll-up; mosh also handles scroll *regions* (DECSTBM) and downward scroll.
  Minor bandwidth, not correctness.
- **`CSI 1 J` (erase-above) divergence from vt100** — *small, inherited.* The
  differential emulator test (`tests/differential_emulator.rs`) found that our
  alacritty backend, on `CSI 1 J` with the cursor on row 1, leaves row 0 intact,
  whereas vt100/xterm clear it ("erase above, inclusive"). alacritty is correct
  for cursor rows >= 2 and for `CSI 0 J`/`CSI 2 J`. Repro:
  `\x1b[1;1H!\x1b[2;1H\x1b[1J`. Rare in practice; a fix would live in (or be
  worked around above) the alacritty dependency.
