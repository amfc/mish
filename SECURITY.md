# Security model

mish's trust model lives at the QUIC/TLS boundary. This documents what we
*enforce and test* versus what we *rely on QUIC (quinn) to enforce*, so the
boundary is explicit.

## Threat model

- The **SSH channel** used for bootstrap is authenticated and confidential
  (that's the user's existing trust anchor). The `MISH CONNECT` line — UDP port,
  server cert, and the minted **client cert + key** — travels only over it.
  - With `--bootstrap=ssh` (the default when `ssh` is present) this is the system
    OpenSSH client, with its full host-key / agent / config handling.
  - With `--bootstrap=builtin` the SSH layer is our own [`russh`] client. It
    still verifies the server against `~/.ssh/known_hosts` and **rejects a key
    mismatch**, but — unlike OpenSSH's interactive prompt — an *unknown* host is
    accepted trust-on-first-use (logged, not persisted). So the bootstrap channel
    is confidential and integrity-protected against a passive attacker, but a
    first-contact active MITM on an unknown host is not caught; `--bootstrap=ssh`
    is the stricter choice when that matters. Auth supports the ssh-agent,
    identity files (incl. **passphrase-protected** keys, prompted on the TTY),
    keyboard-interactive, and password — the latter two prompt for and send a
    secret, but only over this confidential, host-verified channel. `ProxyJump`
    tunnels the SSH bootstrap through jump hosts (each host-key-verified the same
    way). See [`FUTURE_WORK.md`](FUTURE_WORK.md) for remaining gaps.

[`russh`]: https://crates.io/crates/russh
- The **UDP/QUIC path** is hostile: an attacker can observe, drop, duplicate,
  corrupt, replay, and inject packets, and can spoof source addresses.

## What we enforce and test

| Property | Mechanism | Test |
|---|---|---|
| Only the SSH-authenticated party can connect / inject input | mutual TLS — server mints + pins a per-session client cert (`PinnedClientCertVerifier`) | `mish-quic/tests/auth.rs`, `mosh/tests/auth_e2e.rs` |
| Server impersonation rejected | client pins the server cert | `auth.rs`, `auth_e2e.rs` (`real_client_rejects_wrong_server_cert`) |
| 0-RTT replay closed | TLS early data disabled (`max_early_data_size == 0`) | `config.rs::early_data_is_off` |
| Tampering can't corrupt state | QUIC AEAD rejects bit-flipped packets → SSP heals | `wire_attacks.rs::tampered_…` |
| Replay/duplication can't double-apply | QUIC packet-number replay window + idempotent, sequence-numbered SSP diffs | `wire_attacks.rs::duplicated_…`, `mish-ssp` `core_unit`/`sim_convergence` |
| Off-path injection ignored | no valid connection / AEAD failure | `wire_attacks.rs::off_path_…` |
| Pre-handshake junk doesn't exhaust the server | quinn endpoint drops invalid packets | `wire_attacks.rs::server_survives_pre_handshake_junk_flood` |
| Client key not leaked to logs | only on the SSH-tunneled stdout line, never stderr | `mosh/tests/key_hygiene.rs` |
| Malformed/hostile SSP input is safe | no-panic, bounded memory, compression-bomb cap | `fuzz_hostile.rs`, `fuzz_driver_live.rs`, `instruction.rs` |
| A shared-session viewer can't OOM the server with an absurd terminal size | the viewer-screen crop clamps client-reported dimensions to the `MAX_SCREEN_CELLS` budget before allocating | `screen.rs` `resized_view_*` (proptest), `fuzz/.../resized_view.rs` |
| Builtin bootstrap rejects a *changed* host key | `classify_host_key` over russh `check_known_hosts` (match→accept, mismatch→refuse, unknown→TOFU) | `bootstrap.rs` `host_key_{matching,mismatch,unknown}_*` |
| Builtin bootstrap can't be shell-injected | `shell_quote` single-quote escaping of the remote command/session name | `bootstrap.rs` `shell_quote_resists_injection_in_real_sh` (real `/bin/sh`), `shell_quote_round_trips_through_split` |
| Hostile/buggy server can't exhaust client memory at bootstrap | bounded `MISH CONNECT` scan (`MAX_CONNECT_SCAN`, both transports) | `bootstrap.rs` `scan_connect_*`, `bootstrap_parse` fuzz target |
| Bootstrap parsers are panic-free on arbitrary bytes | proptest + coverage-guided libFuzzer | `bootstrap.rs` `fuzz_parse_never_panics`, `fuzz/.../bootstrap_parse` |

## What we rely on QUIC (quinn) to enforce — not separately re-tested

These are core QUIC guarantees; re-testing them would mean re-testing quinn (and
would require raw spoofed-packet crafting against the QUIC state machine). We rely
on quinn's defaults, which we do not disable:

- **Connection-migration / roaming-hijack protection.** A spoofed packet copying
  a client's connection ID from a new source address triggers QUIC **path
  validation** (PATH_CHALLENGE/RESPONSE); an attacker who can't complete it can't
  redirect the server's output. Legitimate migration *is* tested end-to-end
  (`mish-madsim` `full_stack_transparency_with_roaming`); the adversarial case is
  quinn's path validation, left at its default-on setting.
- **3× anti-amplification.** The server never sends more than 3× an unvalidated
  peer's bytes, so it can't be used as a spoofed-source reflector. Enforced by
  quinn per RFC 9000 §8.1.
- **Header protection and AEAD** for all 1-RTT packets.

## Reattach / persistent sessions (`--session`)

A named persistent session (`mish-server --session NAME`, NEXT_FEATURES.md #2)
records the live session in a **`0600`, user-only** file under the user's runtime
dir (`$XDG_RUNTIME_DIR/mish/<name>.session`), holding the session's `MOSH
CONNECT` line — including the reused per-session client cert/key — so a later
`mish host --session NAME` reattaches to the running daemon.

This keeps a credential **at rest**, a step down from the otherwise memory-only
key. The exposure is bounded: the file is readable only by the user (and root),
and **anyone who can read it already has shell access as that user on the host**,
so they never needed the mish session to act as them — the registry adds no new
capability to an attacker. The trust anchor for *who may reattach* remains the SSH
login that launches the lookup. Socket-free reattach is the reason a key lives at
rest at all (the running daemon's cert verifier is fixed at startup, so a freshly
SSH'd lookup must reuse the recorded credential rather than mint a new one); a
zero-key-at-rest variant would require a daemon control socket (deferred). Stale
entries (after an abrupt daemon death) are reaped on the next lookup by a
liveness (`kill(pid, 0)`) check. Persistence is **opt-in** (`--session`); the
default remains a fresh per-connection session.

## Shared multi-client sessions (`--shared`)

A shared session (`mish-server --shared`) lets **several clients attach to one
session at the same time** — one read-write **owner** plus any number of
read-only **viewers** (NEXT_FEATURES.md, "multi-client attach"). The security
properties:

- **Same trust boundary as reattach — not a new one.** Every attaching client
  authenticates with the *same* per-session mutual-TLS credential, delivered over
  SSH and recorded in the `0600` registry file above. So "who may attach" is
  exactly "who has shell access as that user on the host" (or to whom that user
  hands the SSH bootstrap) — `--shared` adds no new way in. It does **not** grant
  cross-user access: a second user gets in only if they could already obtain the
  session credential, which already implies shell access as the owner.
- **Viewers are read-only at the source.** A viewer's keystrokes and resizes are
  dropped **server-side** in `persist::attach` before they reach the PTY — the
  shell never sees them. Read-only is enforced where input is applied, not by
  asking the client to behave. There is exactly one writer slot (the owner);
  while it's held, every other attachment is a viewer.
- **A viewer's reported size can't exhaust server memory.** Because the owner
  drives the shell geometry, a viewer's screen is cropped to *its own* reported
  terminal size (`Screen::resized_view`) — and that size is client-controlled
  (it rides the viewer's `UserStream` resize). The crop **clamps** the
  dimensions (`MAX_VIEW_DIM`, the same cell budget as the `apply_diff`
  `MAX_SCREEN_CELLS` guard) before allocating, so a read-only viewer reporting an
  absurd terminal (e.g. `65535×65535`) can't OOM the shared server. Bounded +
  panic-free for any dimensions, covered by a proptest and the `resized_view`
  libFuzzer target.
- **All attached clients see all output.** A shared session is a broadcast of the
  one screen to every client, so anyone attached can read everything on it
  (including anything the owner types that echoes). Treat attaching someone as
  handing them a live view of your terminal. Sharing is **opt-in** (`--shared`,
  itself behind a default-on `multi-client` build feature that can be compiled
  out entirely); the default is a single-client session.

**Deferred:** an owner-issued, per-viewer *grant* (so a non-owner could be let in
without the full session credential) and runtime write-token handoff between
attached clients — both would need per-client minted certs and an in-session
control protocol, out of scope for v1.

## Port forwarding (`-L` / `-R`)

`ssh -L`/`-R`-style TCP forwarding (NEXT_FEATURES.md #3) tunnels connections over
**bidirectional QUIC streams** inside the existing mutually-authenticated
connection — **no new crypto and no new auth surface**: only the
SSH-authenticated party (the one who read the minted client cert/key over SSH)
can open a stream at all. Forwarding is the one feature that opens a *network*
surface, so the posture is deliberately conservative.

- **Default deny on the server — opt-in, per session.** The server refuses all
  forwarding (`-L` streams dropped, `-R` requests NAK'd) **unless launched with
  `--allow-forward`**. There is no ambient forwarding capability; the server has
  to be told. (The SSH-bootstrapping `mish-client` passes `--allow-forward`
  automatically when the user requests a `-L`/`-R`, so the common case still works
  out of the box — but a manually-launched, reattached, or shared server that was
  *not* started for forwarding stays locked down.)
- **Off until explicitly requested, per forward.** Even with the server allowing
  it, no listener or tunnel exists unless the user passes `-L`/`-R` on the client.
- **The authenticated peer is the owner.** A `-L` lets the client make the server
  dial a target, and `-R` lets the server listen on the client's behalf. Because
  the connecting party is the SSH-authenticated user — who could already run
  arbitrary commands on the host — honoring their explicit forward request (with
  the server opted in) is not a privilege escalation (ssh's `AllowTcpForwarding`
  posture). In a `--shared` session forwarding is granted to the **owner only**;
  read-only viewers cannot open tunnels.
- **The genuinely new surface — a hostile server reaching into the client's
  localhost via `-R` — is closed.** When the server opens a `ForwardedConnection`
  stream, the client dials **only a target it explicitly configured** for that
  `-R` bind, keyed by the requested bind identity; a connection for any other
  bind is refused without dialing. So a compromised/malicious server cannot use
  `-R` to reach arbitrary addresses on the client. (Tested:
  `port_forward.rs::client_refuses_unconfigured_forwarded_connection`.)
- **Bounded.** Each live tunnel is one QUIC stream; the concurrent-stream cap
  (`MAX_SIDE_CHANNELS`, 256) bounds simultaneous tunneled connections, per-stream
  flow control bounds memory, and the framed `StreamHello`/`ForwardAck` control
  messages are size-capped and decode panic-free on arbitrary bytes (the
  `fuzz_hostile` discipline — `forward.rs` codec tests).
- **Listener lifetime.** A `-R` listener is tied to its control stream: tearing
  the forward down (detach/exit) or a dead connection frees the bound port.

What is **relied on, not separately enforced:** once a server is opted in
(`--allow-forward`) there is no per-target allow/deny policy (ssh's
`PermitOpen`/`PermitListen`). A `-L` can dial any host the server can reach, and a
`-R` can bind any address the server may bind. A target allowlist is tracked as
future work; today the controls are the default-deny `--allow-forward` gate, the
owner-only grant in shared sessions, and the client-side `-R` target check.

| Property | Mechanism | Test |
|---|---|---|
| Forwarding off unless the server opts in | `--allow-forward` required; default refuses `-L`, NAKs `-R` | `port_forward.rs::disabled_forwarding_is_refused` |
| Forwarding only when the client requests it | no listener/stream without `-L`/`-R` | (by construction) |
| Hostile server can't reach unconfigured client-local addrs via `-R` | client dials only configured `-R` targets | `port_forward.rs::client_refuses_unconfigured_forwarded_connection` |
| Forwarding control messages are panic-free / bounded | size-capped framing + `Option`-returning decode | `forward.rs::decode_is_panic_free_on_garbage` |

## Follow-ups (tracked)

- **Per-target forwarding allowlist** (`PermitOpen`/`PermitListen`-style). Today
  forwarding is gated by the default-deny `--allow-forward` opt-in plus the
  authenticated-owner model; a host/port allow/deny policy is future work
  (NEXT_FEATURES.md).
- **Zeroize the in-memory client key.** It currently lives as a `Vec<u8>` in
  `SessionAuth`/`Bootstrap`; wrapping it so it's wiped on drop (and suppressing
  core dumps via `RLIMIT_CORE`) is tracked with the broader secrecy adoption.
