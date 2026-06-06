# Deliberately NOT implementing

A reverse to-do list: things from upstream mosh (or that a porter might reach
for) that we have decided **not** to port, with the reason. Keeping this explicit
stops well-meaning contributors from re-adding legacy cruft, and documents that
an omission is a *decision*, not an oversight.

If you think one of these should move back onto the roadmap, open an issue and
argue the case — don't just add it.

## Superseded by QUIC (no action — QUIC does it better)

- **Client UDP port-hopping / explicit roaming re-pin.** QUIC connection
  migration handles IP/port changes natively (tested: `madsim_fullstack`
  roaming). mosh's hand-rolled port survey is unnecessary.
- **DSCP/ECN socket setup, hand-rolled MTU/PMTUD management.** QUIC owns
  congestion control and does DPLPMTUD by default. (We do *want* an ECN→SSP
  frame-rate signal at the app layer — see the roadmap — but not the socket
  plumbing.)
- **Length-disguising chaff + per-frame PRNG padding.** QUIC encrypts and pads;
  re-doing it at the SSP layer is redundant.
- **15-bit fragment-number ceiling / final-bit wire packing.** A legacy mosh wire
  detail; our fragmentation is its own format (wire compatibility is a non-goal).
- **EMSGSIZE-driven MTU shrink-and-retry.** Largely subsumed by quinn's DPLPMTUD,
  which handles the black-hole case more principledly.

## C++/POSIX portability cruft (obsolete under Rust)

- **`util/pty_compat.cc`** — Solaris/AIX `forkpty`/`cfmakeraw` shims. `portable-pty`
  covers the platforms we target.
- **`util/select.{cc,h}`** — `pselect`/`select` wrapper + Cygwin bug workaround.
  We use tokio/`mio`.
- **`util/swrite.cc`** — partial-write loop. Rust's `write_all` / `AsyncWriteExt`.
- **`util/timestamp.cc`** — multi-clock fallback (`mach_absolute_time`,
  `gettimeofday`). `std::time` + our injectable `Clock`.
- **`util/dos_assert.h`, `util/fatal_assert.h`** — subsumed by `Result` / `panic!`.
- **`is-utf8-locale.cc`, `inpty.cc`, `hold-stdin`, `print-exitstatus`** — C++/shell
  test scaffolding; replaced by Rust tests.

## Crypto that TLS 1.3 / rustls makes moot

- **Apple CommonCrypto / `--with-crypto-library` (openssl|nettle|apple-common-crypto).**
  Crypto is rustls (ring); no pluggable backend.
- **Deprecated low-level OpenSSL AES path, Nettle OCB backend.** N/A.
- **Manual 2^47-block OCB usage limit / session-kill.** TLS 1.3 automatic
  key-update handles rekeying.
- **OCB-AES / encrypt-decrypt / base64 / nonce-increment unit tests.** The
  primitives they tested don't exist in our stack.

## Build / packaging machinery

- **Autotools** (`configure.ac`, `Makefile.am`), pkg-config, static-link knobs,
  protobuf-compiler. We use Cargo.
- **`--enable-syslog` / `--with-utempter` as configure-time options.** If we port
  the *features* (syslog logging, utmp accounting — on the roadmap), they'll be
  runtime behavior, not autoconf switches.
- **ufw firewall profile, bash completion, debian/fedora/macOS packaging.** Out of
  scope for the core project.

## Terminal state mosh deliberately does NOT sync (and neither do we)

Upstream's `Complete` framebuffer intentionally synchronizes *less* terminal
state than a full emulator; we match that and in places exceed it. These are
**correct omissions**, not gaps: tabs / tab stops, the saved cursor (DECSC/DECRC),
the scrolling region as persistent state, and origin / insert / auto-wrap modes.
The rendered cell grid is what's synced; these affect only how the *server's* own
emulator interprets subsequent bytes, which it does locally.

## Legacy terminal input/rendition features (low value, declined)

Decades-old VT/xterm corners that almost no current program depends on. Porting
them would add code (often on the hot input path) for ~zero real-world payoff —
exactly the kind of protocol cruft a fresh implementation should *not* inherit.

- **DECCKM application-cursor-keys *input* translation (CSI→SS3).** The cursor-key
  *mode* is synced (`Screen::app_cursor_keys`, emitted in `display.rs`, honored by
  the wheel→arrow path), but a real arrow press is forwarded as the local
  terminal's CSI form (`ESC [ A`) and **not** rewritten to SS3 (`ESC O A`) when the
  remote app set DECCKM. In practice every current TUI (vim, less, htop, emacs,
  fzf, tmux) accepts CSI arrows regardless of DECCKM, so this is pure spec
  fidelity. The rewrite would have to live on the raw keystroke path — the most
  regression-sensitive code in the client — discriminate unmodified arrows from
  the Shift-Arrow scrollback sequences, plumb the synced flag into the input task,
  and handle CSI sequences split across reads. High blast radius, ~zero benefit.
- **Legacy mouse encodings X10 (9), VT220-hilite (1001), UTF-8 (1005), urxvt
  (1015).** Obsolete framings. We sync the modern SGR mouse mode (1006) and the
  click/drag/any-motion modes; the legacy encodings are effectively dead.
- **SGR blink (5) and screen-reverse DECSCNM (`?5h`).** Not a *decline* so much as
  blocked at the emulator layer — alacritty models neither as observable cell/
  screen state (no blink flag; no DECSCNM). See `FUTURE_WORK.md`; capturing them
  would need emulator-side work, not a diff-layer change.

## Known inherited divergence (won't fix at our layer)

- **`CSI 1 J` (erase-above) with the cursor on row 1** leaves row 0 intact in our
  alacritty backend, vs. vt100/xterm clearing it. This lives in the alacritty
  dependency (correct for cursor rows ≥ 2 and for `CSI 0 J` / `CSI 2 J`); a fix
  belongs upstream in alacritty, not in a workaround here. See
  `FUTURE_WORK.md` and `tests/differential_emulator.rs`.
