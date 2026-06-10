# Security model

mish's trust boundary sits at the QUIC/TLS layer. This page sets out what mish
enforces and tests itself versus what it relies on QUIC (quinn) to enforce, so
the line between the two is explicit.

## Threat model

The **SSH channel** used for bootstrap is authenticated and confidential. It is
the user's existing trust anchor. The `MISH CONNECT` line (UDP port, server
cert, and the minted client cert and key) travels only over it.

- With `--bootstrap=ssh`, the default when `ssh` is present, this is the system
  OpenSSH client, with its own host-key, agent, and config handling.
- With `--bootstrap=builtin`, the SSH layer is mish's own [`russh`] client. It
  verifies the server against `~/.ssh/known_hosts` and rejects a key mismatch.
  For an unknown host it behaves like OpenSSH's `StrictHostKeyChecking=ask`: it
  prompts on the controlling terminal (showing the SHA256 fingerprint) and, on
  acceptance, records the key to `known_hosts` so a later change is caught as a
  possible MITM. With no terminal to prompt on it fails closed and refuses.
  `$MISH_STRICT_HOST_KEYS` overrides this: `accept-new` records without
  prompting (for automation), `yes` refuses any host not already known. A
  first-contact active MITM is only as strong as the user's verification of the
  displayed fingerprint, so `--bootstrap=ssh` remains the stricter choice when
  that matters. Auth supports the ssh-agent, identity files (including
  passphrase-protected keys, prompted on the TTY), keyboard-interactive, and
  password. The latter two prompt for and send a secret, but only over this
  confidential, host-verified channel. `ProxyJump` tunnels the SSH bootstrap
  through jump hosts, each verified the same way.

The **UDP/QUIC path** is hostile. An attacker can observe, drop, duplicate,
corrupt, replay, and inject packets, and can spoof source addresses.

[`russh`]: https://crates.io/crates/russh

## What mish enforces and tests

| Property | Mechanism | Test |
|---|---|---|
| Only the SSH-authenticated party can connect or inject input | mutual TLS: server mints and pins a per-session client cert (`PinnedClientCertVerifier`) | `mish-quic/tests/auth.rs`, `mish/tests/auth_e2e.rs` |
| Server impersonation rejected | client pins the server cert | `auth.rs`, `auth_e2e.rs` (`real_client_rejects_wrong_server_cert`) |
| 0-RTT replay closed | TLS early data disabled (`max_early_data_size == 0`) | `config.rs::early_data_is_off` |
| Tampering cannot corrupt state | QUIC AEAD rejects bit-flipped packets, SSP heals | `wire_attacks.rs::tampered_…` |
| Replay or duplication cannot double-apply | QUIC packet-number replay window plus idempotent, sequence-numbered SSP diffs | `wire_attacks.rs::duplicated_…`, `mish-ssp` `core_unit`/`sim_convergence` |
| Off-path injection ignored | no valid connection / AEAD failure | `wire_attacks.rs::off_path_…` |
| Pre-handshake junk does not exhaust the server | quinn endpoint drops invalid packets | `wire_attacks.rs::server_survives_pre_handshake_junk_flood` |
| Client key not leaked to logs | only on the SSH-tunneled stdout line, never stderr | `mish/tests/key_hygiene.rs` |
| Malformed or hostile SSP input is safe | no-panic, bounded memory, compression-bomb cap | `fuzz_hostile.rs`, `fuzz_driver_live.rs`, `instruction.rs` |
| A shared-session viewer cannot OOM the server with an absurd terminal size | the viewer-screen crop clamps client-reported dimensions to the `MAX_SCREEN_CELLS` budget before allocating | `screen.rs` `resized_view_*` (proptest), `fuzz/.../resized_view.rs` |
| Builtin bootstrap rejects a changed host key | `classify_host_key` over russh `check_known_hosts` (match accept, mismatch refuse, unknown TOFU) | `bootstrap.rs` `host_key_{matching,mismatch,unknown}_*` |
| Builtin bootstrap cannot be shell-injected | `shell_quote` single-quote escaping of the remote command and session name | `bootstrap.rs` `shell_quote_resists_injection_in_real_sh` (real `/bin/sh`), `shell_quote_round_trips_through_split` |
| Hostile or buggy server cannot exhaust client memory at bootstrap | bounded `MISH CONNECT` scan (`MAX_CONNECT_SCAN`, both transports) | `bootstrap.rs` `scan_connect_*`, `bootstrap_parse` fuzz target |
| Bootstrap parsers are panic-free on arbitrary bytes | proptest plus coverage-guided libFuzzer | `bootstrap.rs` `fuzz_parse_never_panics`, `fuzz/.../bootstrap_parse` |

## What mish relies on QUIC (quinn) to enforce

These are core QUIC guarantees. Re-testing them would mean re-testing quinn, and
would require crafting raw spoofed packets against the QUIC state machine. mish
relies on quinn's defaults, which it does not disable.

- **Connection-migration / roaming-hijack protection.** A spoofed packet copying
  a client's connection ID from a new source address triggers QUIC path
  validation (PATH_CHALLENGE/RESPONSE). An attacker who cannot complete it cannot
  redirect the server's output. Legitimate migration is tested end-to-end
  (`mish-madsim` `full_stack_transparency_with_roaming`); the adversarial case is
  quinn's path validation, left at its default-on setting.
- **3x anti-amplification.** The server never sends more than 3x an unvalidated
  peer's bytes, so it cannot be used as a spoofed-source reflector. Enforced by
  quinn per RFC 9000 section 8.1.
- **Header protection and AEAD** for all 1-RTT packets.

## Reattach and persistent sessions (`--session`)

A named persistent session (`mish-server --session NAME`) records the live
session in a `0600`, user-only file under the user's runtime directory
(`$XDG_RUNTIME_DIR/mish/<name>.session`). The file holds the session's `MISH
CONNECT` line, including the reused per-session client cert and key, so a later
`mish host --session NAME` can reattach to the running daemon.

This keeps a credential at rest, a step down from the otherwise memory-only key.
The exposure is bounded. The file is readable only by the user (and root), and
anyone who can read it already has shell access as that user on the host, so they
never needed the mish session to act as them. The registry adds no new capability
to an attacker. The trust anchor for who may reattach remains the SSH login that
launches the lookup. Socket-free reattach is the reason a key lives at rest at
all: the running daemon's cert verifier is fixed at startup, so a freshly SSH'd
lookup must reuse the recorded credential rather than mint a new one. A
zero-key-at-rest variant would require a daemon control socket (see the
[roadmap](roadmap.md)). Stale entries, left after an abrupt daemon death, are
reaped on the next lookup by a liveness (`kill(pid, 0)`) check. Persistence is
opt-in; the default is a fresh per-connection session.

## Shared multi-client sessions (`--shared`)

A shared session (`mish-server --shared`) lets several clients attach to one
session at the same time: one read-write owner plus any number of read-only
viewers.

- **Same trust boundary as reattach, not a new one.** Every attaching client
  authenticates with the same per-session mutual-TLS credential, delivered over
  SSH and recorded in the `0600` registry file above. So "who may attach" is
  exactly "who has shell access as that user on the host", or whoever that user
  hands the SSH bootstrap to. `--shared` adds no new way in. It does not grant
  cross-user access: a second user gets in only if they could already obtain the
  session credential, which already implies shell access as the owner.
- **Viewers are read-only at the source.** A viewer's keystrokes and resizes are
  dropped server-side in `persist::attach` before they reach the PTY, so the
  shell never sees them. Read-only is enforced where input is applied, not by
  asking the client to behave. There is exactly one writer slot, the owner; while
  it is held, every other attachment is a viewer.
- **A viewer's reported size cannot exhaust server memory.** Because the owner
  drives the shell geometry, a viewer's screen is cropped to its own reported
  terminal size (`Screen::resized_view`), and that size is client-controlled (it
  rides the viewer's `UserStream` resize). The crop clamps the dimensions
  (`MAX_VIEW_DIM`, the same cell budget as the `apply_diff` `MAX_SCREEN_CELLS`
  guard) before allocating, so a read-only viewer reporting an absurd terminal
  (say `65535x65535`) cannot OOM the shared server. Bounded and panic-free for
  any dimensions, covered by a proptest and the `resized_view` libFuzzer target.
- **All attached clients see all output.** A shared session is a broadcast of the
  one screen to every client, so anyone attached can read everything on it,
  including anything the owner types that echoes. Treat attaching someone as
  handing them a live view of your terminal. Sharing is opt-in (`--shared`,
  itself behind a default-on `multi-client` build feature that can be compiled
  out entirely); the default is a single-client session.

A per-viewer grant issued by the owner (so a non-owner could be let in without
the full session credential) and runtime write-token handoff between attached
clients are both out of scope for v1. See the [roadmap](roadmap.md).

## Port forwarding (`-L` / `-R`)

`ssh -L`/`-R`-style TCP forwarding tunnels connections over bidirectional QUIC
streams inside the existing mutually-authenticated connection. There is no new
crypto and no new auth surface: only the SSH-authenticated party, the one who
read the minted client cert and key over SSH, can open a stream at all.
Forwarding is the one feature that opens a network surface, so the posture is
deliberately conservative.

- **Default deny on the server, opt-in per session.** The server refuses all
  forwarding (`-L` streams dropped, `-R` requests NAK'd) unless launched with
  `--allow-forward`. There is no ambient forwarding capability; the server has to
  be told. The SSH-bootstrapping `mish-client` passes `--allow-forward`
  automatically when the user requests a `-L`/`-R`, so the common case works out
  of the box, but a manually launched, reattached, or shared server that was not
  started for forwarding stays locked down.
- **Off until explicitly requested, per forward.** Even with the server allowing
  it, no listener or tunnel exists unless the user passes `-L`/`-R` on the client.
- **The authenticated peer is the owner.** A `-L` lets the client make the server
  dial a target; a `-R` lets the server listen on the client's behalf. Because
  the connecting party is the SSH-authenticated user, who could already run
  arbitrary commands on the host, honoring an explicit forward request (with the
  server opted in) is not a privilege escalation, the same posture as ssh's
  `AllowTcpForwarding`. In a `--shared` session forwarding is granted to the owner
  only; read-only viewers cannot open tunnels.
- **The genuinely new surface is closed.** A hostile server reaching into the
  client's localhost via `-R` is prevented: when the server opens a
  `ForwardedConnection` stream, the client dials only a target it explicitly
  configured for that `-R` bind, keyed by the requested bind identity. A
  connection for any other bind is refused without dialing. So a compromised
  server cannot use `-R` to reach arbitrary addresses on the client. (Tested:
  `port_forward.rs::client_refuses_unconfigured_forwarded_connection`.)
- **Bounded.** Each live tunnel is one QUIC stream. The concurrent-stream cap
  (`MAX_SIDE_CHANNELS`, 256) bounds simultaneous tunneled connections, per-stream
  flow control bounds memory, and the framed `StreamHello`/`ForwardAck` control
  messages are size-capped and decode panic-free on arbitrary bytes.
- **Listener lifetime.** A `-R` listener is tied to its control stream: tearing
  the forward down (detach or exit) or a dead connection frees the bound port.

What is relied on rather than separately enforced: once a server is opted in
(`--allow-forward`) there is no per-target allow/deny policy (ssh's
`PermitOpen`/`PermitListen`). A `-L` can dial any host the server can reach, and a
`-R` can bind any address the server may bind. A target allowlist is on the
[roadmap](roadmap.md). Today the controls are the default-deny `--allow-forward`
gate, the owner-only grant in shared sessions, and the client-side `-R` target
check.

| Property | Mechanism | Test |
|---|---|---|
| Forwarding off unless the server opts in | `--allow-forward` required; default refuses `-L`, NAKs `-R` | `port_forward.rs::disabled_forwarding_is_refused` |
| Forwarding only when the client requests it | no listener or stream without `-L`/`-R` | (by construction) |
| Hostile server cannot reach unconfigured client-local addrs via `-R` | client dials only configured `-R` targets | `port_forward.rs::client_refuses_unconfigured_forwarded_connection` |
| Forwarding control messages are panic-free and bounded | size-capped framing plus `Option`-returning decode | `forward.rs::decode_is_panic_free_on_garbage` |
