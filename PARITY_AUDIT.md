# mish vs. upstream mosh — parity audit

Independent comparison of `mish` (Rust, QUIC) against upstream `mosh` (C++, UDP/OCB),
done by fanning a verification agent over each subsystem (terminal parser, display/diff,
network/SSP, statesync, client/overlay, server/util/bootstrap, crypto/security, build/CLI,
test suite). Every claim below was re-checked against the actual Rust tree before being
kept; 3 first-pass findings were refuted and dropped. "DOC'd" = already called out in
`FUTURE_WORK.md`/`README.md`/`COVERAGE.md`.

Reminder on declared non-goals (correctly *not* flagged): wire compatibility, zero-RTT
first paint, and replacing OCB/AES/base64/chaff/congestion-control with QUIC+TLS.

---

## 1. High-impact missing features (real correctness / UX gaps, none documented)

### 1.1 Terminal query replies are generated then silently dropped — never written back to the child PTY
The single most impactful finding. mosh routes emulator-generated host answerbacks back to
the shell: `terminalfunctions.cc` builds DA1 (`ESC[?62c`), secondary DA (`ESC[>1;10;0c`),
DSR (`ESC[0n`), CPR (`ESC[<row>;<col>R`), DECRQSS/DECRQM replies, OSC color queries into
`dispatch->terminal_to_host`; `terminal.cc:46` drains it and `completeterminal.cc:58/65`
returns it from `Complete::act()`, and `mosh-server.cc:882` `swrite()`s it to the host fd.

In mish the server emulator is alacritty, which *does* generate these as
`Event::PtyWrite` / `Event::ColorRequest` / `Event::TextAreaSizeRequest`
(`alacritty_terminal-0.26.0/src/term/mod.rs:1262,1268,1284,1337,2090,2147`), but
`mish-terminal/src/emulator.rs` `TermListener::send_event` only handles
`Title`/`ResetTitle`/`ClipboardStore` and discards everything else via `_ => {}`.
`server.rs` calls `emu.feed(&bytes)` but never drains an answerback buffer back into the PTY.

**Impact:** any server-side program that probes the terminal at startup — vim, tmux, less,
`tput`-style detection, CPR-based prompt-width measurement — gets no answer and hangs or
falls back to defaults. **Fix is small** and mirrors the existing title/clipboard plumbing:
capture `PtyWrite` into a byte buffer, drain after each `feed`, feed into the child PTY input.

### 1.2 Instruction zlib compression dropped, not replaced by QUIC
Upstream deflates every instruction (`compressor.cc`). mish sends instruction payloads
uncompressed and QUIC does **not** compensate (QUIC has no payload compression). Higher
bandwidth per frame on exactly the constrained links mosh targets. Add a deflate pass in the
instruction codec.

### 1.3 No connection-status / liveness notification overlay
mosh's `NotificationEngine` renders the blue status bar — "mish: Last contact N seconds
ago", "Last reply…", network-error text, the "[To quit press …]" hint, and connecting/
exiting/timed-out messages. mish has none of it: a stalled link gives the user **no
feedback at all**. This is the headline mosh UX feature; nontrivial to port.

### 1.4 No Ctrl-^ escape key, Ctrl-Z suspend, or `MOSH_ESCAPE_KEY`
The client has no escape-key handling (mosh's `Ctrl-^` then `.` to quit, literal passthrough,
configurable key) and no `SIGTSTP`/Ctrl-Z suspend. Today only `Ctrl-]` detach exists.

### 1.5 No SIGCONT/resume handling
The client installs only a `SIGWINCH` handler. After Ctrl-Z → `fg` (or any stop/cont), it
does **not** re-enter raw mode or repaint — the session is left in a broken terminal state.
Raw mode is only restored on `Drop` (process exit).

### 1.6 Server does not authenticate the client (TLS `no_client_auth`)
mosh's shared session key means the server has cryptographic assurance that input came from
the SSH-authenticated party. mish's QUIC config authenticates only server→client; the
server accepts input from anyone who reaches the port. **Security regression**, undocumented.
(Note: the client *does* pin the server cert — see §6 — so the README's "demo uses insecure
TLS verification" line is stale, but the *client-auth* direction is the real gap.)

---

## 2. Medium missing features

**Terminal / display**
- Screen-wide reverse video **DECSCNM (`ESC[?5h`)** tracked+synced by mosh; alacritty doesn't
  model it and `Screen` has no field for it (appears twice across parser & framebuffer dims).
- Terminal **bell (BEL)** never synced or emitted — mosh syncs it; alacritty surfaces
  `Event::Bell`, dropped by the same `_ => {}`.
- User-input **SS3→CSI cursor-key translation** for application-cursor-keys mode (DECCKM) not
  done — arrow keys send the wrong form to apps that set DECCKM.

**Network / SSP**
- **ECN congestion signal** that throttles SSP frame rate absent.
- `attempt_prospective_resend_optimization` not ported.
- `MOSH_SERVER_SIGNAL_TMOUT` semantics repurposed; the SIGUSR1-conditional idle shutdown of
  disconnected sessions is not implemented (also surfaces under server & build dims).

**State sync / prediction**
- **`ECHO_TIMEOUT` (50 ms late-ack)** + `input_history`/`set_echo_ack`/`wait_time` machinery
  absent — affects prediction-ack timing fidelity.
- No bulk-input/paste guard that disables prediction for large reads (mosh suppresses
  prediction on big pastes to avoid flicker).
- Prediction mode hardcoded `Adaptive`; no `--predict` / `MOSH_PREDICTION_DISPLAY`.
- Cursor prediction not validated against the server cursor (no `ConditionalCursorMove`
  `get_validity`) — mispredicted cursor can persist.
- Glitch/long-pending trigger is a coarse boolean, missing the time-based
  `GLITCH_THRESHOLD`/`GLITCH_FLAG_THRESHOLD` escalation (DOC'd).

**Server / bootstrap**
- No **utmp/wtmp** login accounting (DOC'd), no **syslog** connection logging, no
  **RLIMIT_CORE** core-dump suppression.
- No UTF-8 native-locale validation / `-l` fallback (DOC'd); child not started as a **login
  shell**, missing `TERM`/`NCURSES`/`STY`/`PWD` setup (DOC'd).
- `-s`/`SSH_CONNECTION` interface binding and `-i`/`--bind-server` modes missing; server
  always binds `0.0.0.0`.

**CLI / bootstrap plumbing**
- No `--predict`/`-a`/`-n`/`--predict-overwrite` speculative-echo control.
- `-p`/`--port` (client) and server `-p` range plumbing mostly inert.
- `--ssh` value not shell-split; bootstrap omits `ssh -tt`/`-n`/`--no-ssh-pty`.

---

## 3. Low / minor missing features

- **CSI 1 J** with cursor on row 1 leaves the row above intact, diverging from vt100/xterm
  (DOC'd, inherited from alacritty).
- **SGR blink (5)** dropped from cell renditions.
- Legacy **mouse encodings/modes** not modeled: X10 (9), VT220-hilite (1001), UTF-8 (1005),
  urxvt (1015).
- Client exit does not reset mouse/paste/reverse modes on the main screen.
- Icon name (OSC 1) collapsed into window title; no title stack; **no `[mosh]` title prefix**
  (the prefix is undocumented as a gap).
- Scroll optimization is whole-screen-up only; no DECSTBM sub-region/downward scroll (DOC'd).
- Shutdown handshake completion weaker than upstream's three legs.
- `apply_diff` doesn't enforce `echo_ack` monotonicity / `diff_from` invariant.
- `PredictMode::Experimental` not implemented; adaptive SRTT gate uses a single RTT threshold
  instead of `send_interval` with hysteresis; underline flagging static not latency-driven;
  `MOSH_PREDICTION_OVERWRITE` (insert vs overwrite) absent.
- No client `-v` verbose / diff self-check mode; **Ctrl-L** does not force a full repaint.
- Initial window size hardcoded **80x24** instead of `TIOCGWINSZ` from stdin; child PTY
  `IUTF8` input flag never set (kernel erase of multibyte chars in cooked mode).
- `mish-server` lacks `--version`/`--help`/banner; no `-v`.
- No `--family`/`-4`/`-6`; no `--no-init` (`MOSH_NO_TERM_INIT`, suppress smcup/rmcup); no
  `--experimental-remote-ip`; no `-c` color advertisement (TERM hardcoded).
- `MOSH_PREDICTION_DISPLAY`/`MOSH_PREDICTION_OVERWRITE` env vars not honored.
- *Partial:* no EMSGSIZE-driven MTU shrink-and-retry — but quinn's DPLPMTUD (on by default)
  covers the black-hole case more principledly; this is largely subsumed by QUIC (non-goal).

---

## 4. Test-harness gaps (mosh tests with no Rust equivalent)

**Medium value:**
- **No tmux/real-terminal reference harness** — rendering is never validated end-to-end
  against an *independent real terminal* (the differential test uses the `vt100` crate, not a
  real emulator). mosh's whole e2e suite is tmux-driven.
- **No negative security test** — nothing asserts that a client trusting the wrong cert, or an
  unauthenticated client, is rejected. (Pairs with §1.6.)
- **No performance/throughput benchmark** equivalent to `benchmark.cc` (diff-engine hot loop).

**Low value:**
- No round-trip test for region/downward scroll, reverse-video, bell, or blink.
- Sim harness lacks asymmetric-loss / congestion-feedback / ECN scenarios.
- UserStream diff/subtract drops mosh's prefix-equality assertions (silently tolerates
  divergent ancestors); no counterpart to `Complete::compare`'s cell-divergence reporter.
- No cursor-prediction-divergence or insert/overwrite prediction tests.
- No coverage for utmp/syslog/motd/locale-validation/SIGUSR1 server behaviors.
- No regression guard against the server busy-poll/100%-CPU spin (a bug they already fixed).
- mosh's curated fuzz corpora (`terminal_corpus`, `terminal_parser_corpus`) not carried into
  the Rust fuzz targets; no `ntester.cc` / `parse.cc` / `termemu.cc` equivalents.
- *Partial:* no release pipeline / OSS-Fuzz CIFuzz (rustfmt gate **does** exist — ci.yml:23).

---

## 5. Outdated / legacy — recommend do NOT port

**Strongly skip (C++ portability cruft, fully obsolete under Rust/QUIC):**
- `util/pty_compat.cc` — Solaris/AIX forkpty + cfmakeraw shim.
- `util/select.{cc,h}` — pselect/select wrapper + Cygwin bug workaround.
- `util/swrite.cc` — partial-write loop (Rust `write_all`).
- `util/timestamp.cc` — multi-clock fallback (`mach_absolute_time`, `gettimeofday`).
- `util/dos_assert.h`, `util/fatal_assert.h` — subsumed by `Result`/`panic!`.
- **Autotools** (`configure.ac`/`Makefile.am`), protobuf-compiler, pkg-config, static-link knobs.
- **Apple CommonCrypto / `--with-crypto-library`** (openssl|nettle|apple-common-crypto) — moot.
- Deprecated low-level OpenSSL AES path, Nettle OCB backend; the manual 2^47-block OCB
  usage limit / session-kill (TLS 1.3 auto key-update handles it).
- OCB-AES / encrypt-decrypt / base64 / nonce-incr unit tests — correctly N/A.
- `is-utf8-locale.cc`, `inpty.cc`, `hold-stdin`, `print-exitstatus` — C++/shell scaffolding.

**Skip / out of scope (packaging & build knobs):**
- ufw firewall profile, bash_completion, debian/fedora/macosx packaging.
- `--enable-syslog` / `--with-utempter` as *configure-time* options — port the *feature* (see
  §2) but not the autoconf machinery.
- 15-bit fragment-number ceiling / final-bit wire packing — legacy wire detail.

**Correctly already superseded by QUIC (no action):**
- Client UDP port-hopping, DSCP/ECN socket setup, server re-pin roaming → QUIC migration.
- Length-disguising chaff + per-frame PRNG → QUIC pads/encrypts.
- Hand-rolled MTU/PMTUD management → QUIC DPLPMTUD.

**Correctly NOT synced (mosh's `Complete` deliberately syncs *less* terminal state; Rust
already meets or exceeds it):** tabs, saved cursor, scrolling region, origin/insert/auto-wrap
modes.

---

## 6. Notable corrections (first-pass findings that were refuted or were already correct)

- **Cert pinning is real, not stubbed.** README/FUTURE_WORK say the demo "uses insecure TLS
  verification" and list SSH-bootstrapped cert pinning as deferred — but the actual binaries
  already pin the cert printed over SSH. The docs are stale; the *client-side* trust model is
  fine. (The open gap is *client* auth — §1.6.)
- **Refuted:** "diff only detects whole-screen scroll-up and repaints regions row-by-row" —
  the scroll-region case is handled adequately; only sub-region optimization is missing (§3).
- **Refuted:** NamedColor discriminants 259–268 falling to default — not actually a defect.
- **Refuted:** length-disguising as a regression — correctly dropped, QUIC pads (§5).
- `render.rs::render_full`'s wide-char spacer handling is buggy but **dead code** (the client
  paints via `display::new_frame`), so harmless today — worth a comment or removal.

---

## Suggested priority order

1. **§1.1 PTY answerback drain** — small fix, high impact (fixes app probes/hangs).
2. **§1.6 + §4 client auth** — security regression; add mutual TLS + a negative test.
3. **§1.3 status/liveness overlay** — the signature mosh UX feature.
4. **§1.5 SIGCONT + §1.4 escape/suspend** — basic interactive-shell hygiene.
5. **§1.2 instruction compression** — bandwidth on constrained links.
6. **§2 bell, DECSCNM, DECCKM cursor-keys** — small, mechanical terminal-state additions.
