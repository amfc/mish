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
- **CLI/bootstrap** — *client done.* `mish-client` now has `--predict`/`-a`/`-n`
  + `MOSH_PREDICTION_DISPLAY`, `--ssh` shell-splitting with `ssh -n`/`-tt` +
  `--no-ssh-pty`, `--no-init` (`MOSH_NO_TERM_INIT`, suppresses the alternate
  screen), and `--version` (`bootstrap::shell_split`, `client_cli.rs` tests).
  *Remaining (lower value):* server `--version`/`--help`/banner, `-c` color
  advertisement, and `--predict-overwrite` (needs the unimplemented
  `predict_overwrite` engine path).
- **Initial window size from `TIOCGWINSZ` + PTY `IUTF8` input flag** — *done.*
  The client already reports the real size via `crossterm::size()`, and the
  server now sets `IUTF8` on the PTY (via the master fd, which shares the
  line-discipline termios on Linux) so cooked-mode erase deletes whole multibyte
  characters (`pty::enable_iutf8`, tested). The **three-leg shutdown handshake**
  is in place and loss-tolerant — the core resends `SHUTDOWN_NUM` at the frame
  rate until acked, so both sides reach a clean close even under datagram loss
  (`core_unit::shutdown_converges_under_loss`).
- **Test harnesses** — *done.* A **diff-engine throughput benchmark** (mosh's
  `benchmark.cc` equivalent) at `mish-terminal/examples/diff_bench.rs` times
  `display::new_frame` + the `apply_diff` round-trip across scrolling/typing/
  full-repaint workloads (`cargo run -p mish-terminal --release --example
  diff_bench`). A **real-PTY reference harness**
  (`mosh/tests/real_terminal_reference.rs`) feeds the output of a real program
  on a real kernel PTY to our emulator *and* the independent `vt100` renderer
  and asserts they agree — real bytes, independent oracle, beyond the synthetic
  differential grammar. *Optional future extension:* a tmux/xterm-driven oracle
  (a true terminal) where those are installed; `vt100` is the portable
  always-available independent renderer used here.

## Built-in SSH bootstrap (`--bootstrap=builtin`)

The session bootstrap can run over a builtin, pure-Rust SSH client ([`russh`])
instead of the system `ssh` binary, selected with `--bootstrap` (`auto` — the
default — uses the system `ssh` if it's on `PATH`, else the builtin client; `ssh`
and `builtin` force one). This is the groundwork for an `mish` that runs where
upstream mosh never could — primarily **Windows**, which has no external `ssh`.

**Now implemented** (all pure-Rust, no C deps — important for the Windows goal):

- **Auth.** ssh-agent (Unix) → identity files, **prompting for a passphrase on an
  encrypted key** (`rpassword`) → **keyboard-interactive** → **password**. The
  method order follows the server's advertised set; the two interactive
  fallbacks prompt only when stdin is a terminal.
- **`~/.ssh/config`.** `HostName`/`Port`/`User`/`IdentityFile`/`ProxyJump` are
  resolved via `russh-config` (command-line user/port win); `~` in identity paths
  is expanded. `$MISH_SSH_CONFIG` overrides the config path.
- **ProxyJump.** A jump chain is tunnelled with chained direct-tcpip channels;
  each hop authenticates independently and its handle is held for the session.
- **Host keys.** Checked against `~/.ssh/known_hosts`: mismatch rejected, unknown
  accepted trust-on-first-use.

Remaining, in rough effort order:

- **Windows port itself** — *the actual goal this unblocks.* The builtin
  bootstrap removes the hard `ssh` dependency, but the client/server still use
  Unix PTYs, signals (`SIGWINCH`/`SIGCONT`/`SIGTSTP`), and `libc`. A Windows
  build needs a ConPTY server side and a crossterm-based client side. *Larger.*
  (On Windows the builtin client also needs the named-pipe ssh-agent; the Unix
  socket agent is `#[cfg(unix)]`.)
- **Auth polish.** No passphrase **caching** (re-prompts per key), no
  `IdentitiesOnly`/`AddKeysToAgent`, no PKCS#11. `known_hosts` trust-on-first-use
  is **not written back** (re-warns each run); persisting accepted keys + an
  interactive accept/reject prompt is future work.
- **ssh_config gaps.** `russh-config` handles `Host` wildcards but **not `Match`
  or `Include`**, and we read `ProxyJump` but not `ProxyCommand`. (`ssh2-config`
  is more complete but drags in a `git2` build-dependency → libgit2/openssl/
  libssh2 C libraries, which would break the no-C Windows goal, so it's avoided.)
- **ProxyJump UDP.** Only the **SSH bootstrap** is tunnelled; the mosh UDP session
  still connects directly to the resolved target (mosh roaming isn't tunnelled),
  so the target must be UDP-reachable. Tunnelling UDP would be a larger change.
- **IPv6 UDP target.** Shared with the `ssh` path: the QUIC client endpoint binds
  `0.0.0.0:0` (IPv4), so if the host resolves to an IPv6 address first the
  follow-on QUIC connect fails. The endpoint should bind to match the resolved
  address family.

[`russh`]: https://crates.io/crates/russh
