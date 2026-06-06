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
  - With `--bootstrap=built-in` the SSH layer is our own [`russh`] client. It
    still verifies the server against `~/.ssh/known_hosts` and **rejects a key
    mismatch**, but — unlike OpenSSH's interactive prompt — an *unknown* host is
    accepted trust-on-first-use (logged, not persisted). So the bootstrap channel
    is confidential and integrity-protected against a passive attacker, but a
    first-contact active MITM on an unknown host is not caught; `--bootstrap=ssh`
    is the stricter choice when that matters. Auth uses the ssh-agent or
    unencrypted on-disk keys only (see [`FUTURE_WORK.md`](FUTURE_WORK.md)).

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

## Follow-ups (tracked)

- **Zeroize the in-memory client key.** It currently lives as a `Vec<u8>` in
  `SessionAuth`/`Bootstrap`; wrapping it so it's wiped on drop (and suppressing
  core dumps via `RLIMIT_CORE`) is tracked with the broader secrecy adoption.
