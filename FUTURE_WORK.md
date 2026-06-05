# Future work

Remaining differences from upstream mosh, with rough effort. None are deep
protocol gaps — mostly extra terminal state to sync and a richer prediction
trigger. (Wire compatibility and zero-RTT are explicit non-goals — see README.)

## Terminal features not yet synced

Done: **focus-event mode (DECSET 1004)**, **alternate-scroll (1007)**, and the
**OSC 52 clipboard** are now synced (`Screen::{focus_event, alternate_scroll,
clipboard}`, populated in `Emulator::snapshot`, emitted on change in
`display::new_frame`, round-trip tested in `display_roundtrip.rs`). The clipboard
is monotonic latest-wins (the emulator's listener never reverts to `None`), so it
is excluded from the generic `arb_screen` round-trip and covered by dedicated
directional tests instead.

Remaining:

- **Icon name (OSC 1) / title stack (OSC 22/23)** — *low value / not
  representable.* alacritty folds OSC 0/2 into one `Event::Title` and doesn't
  track icon name or a title stack separately, so this would need emulator-side
  work. Skipped.

## Prediction adaptiveness (mosh parity) — done

`PredictMode::Adaptive` now combines the SRTT gate with a confidence score built
from the prediction track record (`predict.rs`): each `CellPrediction` records
whether it changed the displayed cell (`credit`) vs. merely re-asserting the
existing glyph (mosh's `CorrectNoCredit`). On confirmation, only credited-correct
predictions raise `confidence`; a misprediction resets it to 0 (alongside the
existing glitch suppression). Once `CONFIDENCE_TRIGGER` credited-correct
predictions accumulate, the overlay displays even on a link below the SRTT
trigger. Tested in `predict.rs` (`confidence_enables_adaptive_below_srtt_trigger`,
`correct_no_credit_does_not_build_confidence`, `misprediction_resets_confidence`).

## Server ops plumbing (mish-server)

- **utmp/wtmp accounting, motd, setuid drop, locale validation** — *moderate,
  OS-specific.* Real session/login plumbing the daemon would do in production;
  orthogonal to the protocol.
- **SSH-bootstrapped real cert pinning** — *small.* The demo trusts the cert
  printed over SSH; production could pin it via known_hosts-style storage.

## Misc

- **Diff: scroll-region optimization** — *done.* `display::detect_scroll` now
  recognizes whole-screen scrolls (LF/RI) and DECSTBM sub-regions in both
  directions; the synthesized baseline models the emitted escapes exactly, so the
  round-trip stays exact. Tested in `display_roundtrip.rs` (whole-screen down,
  bottom-fixed region up, header/footer-fixed region down) and stressed by the
  diff fuzzers.
- **`CSI 1 J` (erase-above) divergence from vt100** — *small, inherited.* The
  differential emulator test (`tests/differential_emulator.rs`) found that our
  alacritty backend, on `CSI 1 J` with the cursor on row 1, leaves row 0 intact,
  whereas vt100/xterm clear it ("erase above, inclusive"). alacritty is correct
  for cursor rows >= 2 and for `CSI 0 J`/`CSI 2 J`. Repro:
  `\x1b[1;1H!\x1b[2;1H\x1b[1J`. Rare in practice; a fix would live in (or be
  worked around above) the alacritty dependency.
