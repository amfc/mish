# Deliberately not implementing

A reverse to-do list: things from upstream mosh, or that a porter might reach
for, that mish has decided not to port, with the reason. Keeping this explicit
stops well-meaning contributors from re-adding legacy cruft, and records that an
omission is a decision rather than an oversight.

If you think one of these should move back onto the roadmap, open an issue and
argue the case rather than just adding it.

## Superseded by QUIC

QUIC does these better, so there is nothing to port.

- **Client UDP port-hopping and explicit roaming re-pin.** QUIC connection
  migration handles IP and port changes natively (tested: `madsim_fullstack`
  roaming). mosh's hand-rolled port survey is unnecessary.
- **DSCP/ECN socket setup, hand-rolled MTU/PMTUD management.** QUIC owns
  congestion control and does DPLPMTUD by default. (An ECN-to-SSP frame-rate
  signal at the app layer is on the [roadmap](roadmap.md), but not the socket
  plumbing.)
- **Length-disguising chaff and per-frame PRNG padding.** QUIC encrypts and pads;
  redoing it at the SSP layer is redundant.
- **15-bit fragment-number ceiling and final-bit wire packing.** A legacy mosh
  wire detail. mish's fragmentation is its own format, and wire compatibility is
  a non-goal.
- **EMSGSIZE-driven MTU shrink-and-retry.** Largely subsumed by quinn's DPLPMTUD,
  which handles the black-hole case more principledly.

## C++/POSIX portability cruft

Obsolete under Rust.

- **`util/pty_compat.cc`**: Solaris/AIX `forkpty`/`cfmakeraw` shims.
  `portable-pty` covers the platforms mish targets.
- **`util/select.{cc,h}`**: `pselect`/`select` wrapper plus a Cygwin bug
  workaround. mish uses tokio and `mio`.
- **`util/swrite.cc`**: partial-write loop. Rust has `write_all` and
  `AsyncWriteExt`.
- **`util/timestamp.cc`**: multi-clock fallback (`mach_absolute_time`,
  `gettimeofday`). mish uses `std::time` plus an injectable `Clock`.
- **`util/dos_assert.h`, `util/fatal_assert.h`**: subsumed by `Result` and
  `panic!`.
- **`is-utf8-locale.cc`, `inpty.cc`, `hold-stdin`, `print-exitstatus`**: C++ and
  shell test scaffolding, replaced by Rust tests.

## Crypto that TLS 1.3 / rustls makes moot

- **Apple CommonCrypto and `--with-crypto-library`** (openssl, nettle,
  apple-common-crypto). Crypto is rustls (ring); there is no pluggable backend.
- **Deprecated low-level OpenSSL AES path and Nettle OCB backend.** Not
  applicable.
- **Manual 2^47-block OCB usage limit and session-kill.** TLS 1.3 automatic
  key-update handles rekeying.
- **OCB-AES, encrypt/decrypt, base64, and nonce-increment unit tests.** The
  primitives they tested do not exist in mish's stack.

## Build and packaging machinery

- **Autotools** (`configure.ac`, `Makefile.am`), pkg-config, static-link knobs,
  protobuf-compiler. mish uses Cargo.
- **`--enable-syslog` and `--with-utempter` as configure-time options.** If the
  features (syslog logging, utmp accounting) are ported, they will be runtime
  behavior rather than autoconf switches.
- **ufw firewall profile, bash completion, Debian/Fedora/macOS packaging.** Out
  of scope for the core project.

## Terminal state mosh deliberately does not sync

Upstream's `Complete` framebuffer intentionally synchronizes less terminal state
than a full emulator. mish matches that, and in places exceeds it. These are
correct omissions, not gaps: tabs and tab stops, the saved cursor (DECSC/DECRC),
the scrolling region as persistent state, and origin, insert, and auto-wrap
modes. The rendered cell grid is what's synced; these affect only how the
server's own emulator interprets subsequent bytes, which it does locally.

## Legacy terminal input and rendition features

Decades-old VT/xterm corners that almost no current program depends on. Porting
them would add code, often on the hot input path, for near-zero real-world
payoff.

- **DECCKM application-cursor-keys input translation (CSI to SS3).** The
  cursor-key mode is synced (`Screen::app_cursor_keys`, emitted in `display.rs`,
  honored by the wheel-to-arrow path), but a real arrow press is forwarded as the
  local terminal's CSI form (`ESC [ A`) and not rewritten to SS3 (`ESC O A`) when
  the remote app set DECCKM. In practice every current TUI (vim, less, htop,
  emacs, fzf, tmux) accepts CSI arrows regardless of DECCKM, so this is pure spec
  fidelity. The rewrite would have to live on the raw keystroke path, the most
  regression-sensitive code in the client: it would discriminate unmodified
  arrows from the Shift-Arrow scrollback sequences, plumb the synced flag into
  the input task, and handle CSI sequences split across reads. High blast radius,
  near-zero benefit.
- **Legacy mouse encodings**: X10 (9), VT220-hilite (1001), UTF-8 (1005), urxvt
  (1015). Obsolete framings. mish syncs the modern SGR mouse mode (1006) and the
  click, drag, and any-motion modes; the legacy encodings are effectively dead.
- **SGR blink (5) and screen-reverse DECSCNM (`?5h`).** Less a decline than a
  block at the emulator layer: alacritty models neither as observable cell or
  screen state (no blink flag, no DECSCNM). Capturing them would need
  emulator-side work, not a diff-layer change.

## Known inherited divergence

- **`CSI 1 J` (erase-above) with the cursor on row 1** leaves row 0 intact in the
  alacritty backend, whereas vt100/xterm clear it. This lives in the alacritty
  dependency (it is correct for cursor rows >= 2 and for `CSI 0 J` / `CSI 2 J`), so
  a fix belongs upstream in alacritty rather than as a workaround here. See
  `tests/differential_emulator.rs`.
