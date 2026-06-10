# Roadmap

Work that is not yet done. mish is at mosh feature parity and ships several
features beyond it (scrollback, persistent sessions, multi-client attach, port
forwarding). What follows is the remaining work, roughly by area. None of it is a
core protocol gap. For things mish has deliberately decided not to build, see
[`not-implementing.md`](not-implementing.md).

## Beyond mosh

- **Large clipboard over a reliable stream.** Small OSC 52 clipboard contents
  already sync on the datagram path (latest-wins, `Screen::clipboard`). The
  remaining work moves large payloads onto the reliable side-channel: the datagram
  diff carries a clipboard-epoch marker, and the bytes transfer out-of-band and
  apply when complete. Needs a size cap and a consent policy, since the clipboard
  is a classic exfiltration channel.

## Windows port

The builtin (russh) SSH bootstrap removes the hard dependency on an external `ssh`
binary, which is the main blocker for Windows. The client and server still use
Unix PTYs, signals (`SIGWINCH`/`SIGCONT`/`SIGTSTP`), and `libc`. A Windows build
needs a ConPTY server side and a crossterm-based client side, plus the named-pipe
ssh-agent on the client (the Unix socket agent is `#[cfg(unix)]`).

## Builtin SSH bootstrap

- **Auth polish.** No passphrase caching (it re-prompts per key), no
  `IdentitiesOnly` or `AddKeysToAgent`, no PKCS#11.
- **ssh_config gaps.** `russh-config` handles `Host` wildcards but not `Match` or
  `Include`; mish reads `ProxyJump` but not `ProxyCommand`. (`ssh2-config` is more
  complete but pulls in a `git2` build dependency, which drags in
  libgit2/openssl/libssh2 C libraries and would break the no-C Windows goal, so it
  is avoided.)
- **ProxyJump UDP.** Only the SSH bootstrap is tunnelled through jump hosts; the
  QUIC session connects directly to the resolved target, so the target must be
  UDP-reachable. Tunnelling the UDP session would be a larger change.

## Security

- **Per-target forwarding allowlist** (`PermitOpen`/`PermitListen`-style). Today
  forwarding is gated by the default-deny `--allow-forward` opt-in plus the
  authenticated-owner model; a per-host/port allow/deny policy is future work. See
  [`security.md`](security.md#port-forwarding--l---r).
- **Zeroize the in-memory client key.** It currently lives as a `Vec<u8>` in
  `SessionAuth`/`Bootstrap`; wrapping it so it is wiped on drop ties into the
  broader secrecy adoption.
- **Zero-key-at-rest reattach.** A persistent session records its credential in a
  `0600` file so a freshly SSH'd lookup can reattach. A variant that keeps no key
  at rest would need a daemon control socket. See
  [`security.md`](security.md#reattach-and-persistent-sessions---session).
- **Shared-session grants.** An owner-issued, per-viewer grant (so a non-owner
  could be let in without the full session credential) and runtime write-token
  handoff between attached clients would both need per-client minted certs and an
  in-session control protocol.

## Prediction

- **`predict_overwrite`** (insert vs. overwrite line shifting) and
  **`PredictMode::Experimental`** (per-keystroke epoch reset) are not implemented.
  `--predict-overwrite` and `MOSH_PREDICTION_OVERWRITE` depend on the first.

## Server ops

Lower-value plumbing: syslog connection logging, `-s`/`SSH_CONNECTION` interface
binding, and `STY`/`PWD` unsetting. utmp/wtmp accounting stays deferred:
`portable-pty` hides the slave PTY device name it would need, and writing
`/var/run/utmp` typically requires root or the utmp group.

## SSP

An ECN-to-frame-rate throttle and a SIGUSR1-conditional idle shutdown of
disconnected sessions are unported. Both are largely subsumed by QUIC's congestion
control and are low value.
