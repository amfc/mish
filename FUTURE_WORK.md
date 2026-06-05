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

- **Locale validation** — *done.* `mish::locale` resolves the effective locale
  (LC_ALL > LC_CTYPE > LANG) and, if it isn't UTF-8, forces `LC_ALL=C.UTF-8` for
  the child and warns — the emulator decodes child output as UTF-8, so a
  non-UTF-8 locale would corrupt the rendered (and synchronized) screen. Pure
  decision logic, unit-tested.
- **Root warning** — *done.* The server warns if started as root, which is
  unusual in the SSH-launch model (it normally runs as the connecting user).

Deliberately not done (with rationale):

- **setuid privilege drop** — *not applicable here.* mish-server is launched over
  SSH **as the target user**, so there is no elevated privilege to drop and no
  target uid to drop to. Relevant only to a setuid/root-launched deployment,
  which this isn't.
- **utmp/wtmp accounting** — *blocked + low value.* Recording the session in
  `who`/`w`/`last` needs the slave PTY's device name, which `portable-pty`
  abstracts away, plus write access to `/var/run/utmp` (typically root/utmp-group
  only). Best-effort and untestable here; deferred.
- **motd** — the login shell already prints it; not the server's job.
- **SSH-bootstrapped cert pinning** — *low value.* The cert is exchanged over the
  already-authenticated SSH channel, so it's trusted at handshake time. Pinning
  would only add defense-in-depth against a post-handshake swap; deferred.

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

## Feature/parity backlog (from the second review, medium/low priority)

None of these are correctness or security gaps — the §1 review items
(authentication, answerback, compression, escape/suspend/SIGCONT, status
overlay) are all done. These are the remaining parity polish:

- **Reverse video (DECSCNM `ESC[?5h`) + terminal bell (BEL).** mosh syncs both;
  alacritty surfaces `Event::Bell` (dropped today) and may not model DECSCNM as a
  `Screen` field — needs a transient bell counter and possibly emulator-side work.
- **DECCKM cursor-key translation + legacy mouse encodings; client mode reset on
  exit.** App-cursor-keys mode (SS3 vs CSI for arrows) needs client-side input
  translation keyed on the synced mode; legacy mouse modes X10(9)/hilite(1001)/
  UTF-8(1005)/urxvt(1015) unmodeled; SGR blink (5) dropped from renditions.
  *(Client mode-reset-on-exit and the `[mish]` title prefix are already done.)*
- **Prediction-ack timing + paste guard + cursor validation** — *done* (except
  `PredictMode::Experimental`). The paste guard (no prediction for an input
  batch over 100 bytes), predicted-cursor validation against the server cursor,
  and the time-based glitch trigger (`GLITCH_THRESHOLD` display escalation +
  `GLITCH_FLAG_THRESHOLD` underline, cured by quick confirmations) are ported in
  `predict.rs`; the engine now takes `now_ms` and the client ages it via
  `advance(now)` on every repaint (mosh's 50 ms `wait_time()` poll). The
  `late_ack`/`echo_ack` gate that mosh's `ECHO_TIMEOUT` machinery feeds is
  already how we judge a prediction (`Screen::echo_ack`). *Remaining:*
  `PredictMode::Experimental` (per-keystroke epoch reset) and `predict_overwrite`
  (insert-vs-overwrite line shifting).
- **SSP: ECN frame-rate throttle, `attempt_prospective_resend_optimization`,
  SIGUSR1-conditional idle shutdown of disconnected sessions, `apply_diff`
  echo_ack monotonicity enforcement.**
- **Server ops** — *mostly done.* The child now starts as a **login shell**
  (`$SHELL -l`) with `TERM` set, `RLIMIT_CORE` is suppressed (no core dump can
  leak the client key), and `-4`/`-6`/`--family` select the bind family.
  *Remaining (lower value):* syslog connection logging, `-s`/`SSH_CONNECTION`
  interface binding, and `STY`/`PWD` unsetting. utmp/wtmp stays deferred (blocked
  by portable-pty hiding the pts name).
- **CLI/bootstrap: `--predict`/`-a`/`-n` + `MOSH_PREDICTION_*` env, `-p`/range
  plumbing, `--ssh` shell-split + `ssh -tt`/`-n`/`--no-ssh-pty`, server
  `--version`/`--help`, `--no-init` (`MOSH_NO_TERM_INIT`), `-c` color advertise.**
- **Initial window size from `TIOCGWINSZ` + PTY `IUTF8` input flag.** (The client
  already reports the real size via `crossterm::size()`; IUTF8 may be blocked by
  portable-pty.) Three-leg shutdown-handshake parity.
- **Test harnesses: real-terminal reference (PTY-driven, beyond vt100) and a
  diff-engine throughput benchmark (mosh's `benchmark.cc`).**
