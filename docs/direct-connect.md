# Direct connect (ssh-less fast path)

Normally `mish-client host` bootstraps over SSH: it SSHes in, starts
`mish-server`, and reads a one-time `MISH CONNECT` line carrying a freshly
minted, per-session client cert and key (see the [security model](security.md)).
That SSH round-trip is the slow part of a connect.

**Direct-connect mode removes the SSH step from the hot path.** You pay it
*once*, at enrollment: `mish enroll host` exchanges long-lived certificates over
SSH and pins them on disk. Every connect after that is a single mutually
authenticated QUIC handshake straight to a listening `mish-server` — no SSH, no
per-session handoff.

It is a strict, opt-in add-on. The SSH bootstrap is untouched and remains the
default; nothing here changes how `mish-client host` behaves.

## Model

Two things are persistent, one thing is emphatically not.

- **Server identity — persistent.** `mish-server --listen` keeps a stable
  keypair on disk. Its certificate is what a client pins, so it must survive
  restarts (a rotating identity would break every enrolled client).
- **Enrolled client certs — persistent.** The server keeps an **allow-list**:
  one `*.crt` per enrolled client in a directory. A QUIC handshake is accepted
  only if the client presents a cert whose DER is byte-for-byte one of these.
  Enroll a client to let it in; delete its `.crt` to revoke it. Empty directory
  means "accept nobody".
- **Sessions — NOT persistent.** Each accepted QUIC connection gets its **own
  fresh shell**. A new invocation is a new connection is a new shell; it never
  reattaches to an older process. When a connection dies, its shell is killed and
  reaped immediately. There is no session registry, no `--session`, no
  `--reattach` here.

If you want a shell that outlives disconnects, run **tmux** inside it — that is
the persistence layer, exactly as upstream mosh recommends. What direct mode
gives you on top is roaming: because the transport is QUIC, a connection that
changes IP (laptop sleep, network switch) **migrates** and keeps going without a
reconnect, the same mechanism the SSH-bootstrapped path already uses. You only
land on a fresh shell when a connection has genuinely died.

## Enroll once

```sh
mish enroll user@host
```

This SSHes to `host` (using the system `ssh`; override the command with `--ssh`),
runs `mish-server --enroll-client <your-cert>` on the far side, and:

- generates a long-lived **client identity** for you if you don't have one
  (`<config>/client.key` + `.crt`),
- has the server add your client cert to its allow-list, and
- pins the server's certificate for `host` locally, so a later direct connect
  can authenticate the server without asking SSH again.

Options: `--ssh CMD` (the SSH command, default `ssh`), `--server CMD` (the remote
`mish-server` command, default `mish-server`), and `--name LABEL` (the allow-list
slot name on the server; defaults to your hostname, so re-enrolling from the same
machine rotates your own slot instead of piling up).

## Connect many times

Start the listener on the host (see [Running the listener](#running-the-listener)),
then from an enrolled client:

```sh
mish-client --connect host:PORT
```

`host` selects which pinned server cert to trust (the one `mish enroll host`
saved); `PORT` is the listener's UDP port. The client presents its enrolled
identity, pins the server cert, and opens the QUIC session directly. Bracket an
IPv6 literal as `[::1]:PORT`.

All the usual client flags apply (`--predict`, `--no-init`, `-L`/`-R`, the
escape/scrollback keys). Port forwarding still requires the server to be started
with `--allow-forward`.

## Running the listener

`--listen` takes an optional bind IP and a port. **You choose the bind address**
— there is no mish config file for it and no systemd unit shipped here; wiring
the listener into a supervisor and routing traffic to it is the operator's job.

```sh
# Bind a specific address (e.g. a WireGuard IP on a host):
mish-server --listen 10.99.0.1:60000

# Bind all interfaces (e.g. inside a container behind its own network):
mish-server --listen 0.0.0.0:60000

# A bare port defaults the bind IP to 0.0.0.0:
mish-server --listen 60000
```

On startup the listener prints one machine-readable line to **stdout**:

```
MISH LISTEN <bound-addr>
```

so a supervisor (or a test) can discover the actual bound address, including when
you asked for port `0` and the OS picked one. Everything else goes to stderr.

Paths, both overridable, both defaulting under the config dir:

- `--server-key PATH` — the persistent server identity key (default
  `<config>/server.key`; the cert lives beside it as `server.crt`). Generated on
  first use with `0600` permissions.
- `--authorized-certs DIR` — the enrolled-client allow-list directory (default
  `<config>/authorized`). Created `0700` if missing.

The config dir is `$MISH_CONFIG_DIR`, else `$XDG_CONFIG_HOME/mish`, else
`~/.config/mish`.

The listener has **no** `MISH CONNECT` handoff and **no** signal/idle-exit
timeout — it is meant to be long-lived and supervised. Stop it by stopping the
process.

## Security

Direct mode moves the trust anchor from "a live SSH login each time" to "a
one-time SSH enrollment that pins long-lived certs". The QUIC/TLS boundary is
identical to the bootstrap path — mutual TLS, pinned server cert, 0-RTT off — the
only change is the **client** verifier: instead of pinning one per-session cert,
the server checks the presented client cert against the on-disk allow-list. See
the [security model](security.md#direct-connect-mode---listen) for the full
treatment and the enrollment threat model.
