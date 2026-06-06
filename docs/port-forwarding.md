# Port forwarding (`-L` / `-R`)

`mish` can tunnel TCP connections over its session, exactly like `ssh -L` and
`ssh -R` — something **upstream mosh cannot do at all** (its UDP/OCB transport
has no reliable multiplexed channel). Each forwarded connection rides its own
**bidirectional QUIC stream** inside the *same* mutually-authenticated
connection, so QUIC handles reliability, ordering, flow control, and congestion;
the live screen keeps riding loss-tolerant datagrams alongside.

---

## Using it

The spec format matches ssh: `[bind_address:]port:host:hostport`.

### Local forward (`-L`) — reach a remote service from your machine

```sh
# Browse the remote's localhost:3000 at your own localhost:8080.
mish-client host -L 8080:localhost:3000

# Reach a database only the remote can see.
mish-client host -L 5432:db.internal:5432
```

Your machine listens on the local port; each connection is relayed and the
**server** dials `host:hostport`. Repeat `-L` for multiple forwards.

### Remote forward (`-R`) — expose a local service on the remote

```sh
# Make your local dev server (localhost:3000) reachable as the remote's :9000.
mish-client host -R 9000:localhost:3000
```

The **server** listens on the remote port; each connection there is relayed back
and **your client** dials `host:hostport`. Repeat `-R` for multiple forwards.

### Bind address

Without a `bind_address` the listener binds **loopback** (`127.0.0.1`), as ssh
does without `GatewayPorts`. Pass one explicitly to listen more widely:

```sh
mish-client host -L 0.0.0.0:8080:localhost:3000   # accept from the LAN (-L)
mish-client host -R 0.0.0.0:9000:localhost:3000   # expose to the remote's LAN (-R)
```

A `port` of `0` requests an ephemeral port; for `-R` the client prints the port
the server actually bound.

---

## Security

Port forwarding is the one feature that opens a network surface, so it is
deliberately conservative. See [`SECURITY.md`](../SECURITY.md#port-forwarding--l---r)
for the full threat model. In short:

- **Off until requested.** No listener or tunnel exists unless you pass `-L`/`-R`.
- **Same auth, no new crypto.** Tunnels ride the existing mutually-authenticated
  connection; only the SSH-authenticated party can open them.
- **The client only dials what you configured.** A malicious/compromised server
  cannot use `-R` to reach arbitrary addresses on your machine — the client
  refuses any forwarded connection whose bind it didn't request.
- **Server kill switch.** `mish-server --no-forward` hard-disables all
  forwarding regardless of what the client asks.
- **Bounded.** Each live tunnel is one QUIC stream; the concurrent-stream cap
  (256) bounds simultaneous tunneled connections, and per-stream flow control
  bounds memory.

---

## Caveats / limitations (v1)

- **TCP only** (no `-D` SOCKS / dynamic forwarding, no UDP).
- **IPv6 literals in the spec aren't supported** — the `host:port` colon-splitting
  can't disambiguate them. Use a hostname, or an IPv4 literal. (The bind/dial
  themselves resolve IPv6 fine; only the *spec parser* is limited.)
- A forward that fails to bind (port in use) is reported but doesn't abort the
  session — the shell and the other forwards still come up.
- Forwards last for the session; they're torn down when you detach/exit.

---

## How it works

Every reliable side-channel stream now opens with a small framed `StreamHello`
tag, so one server-side accept loop demultiplexes scrollback history and the
forwarding traffic ([`crate::forward`](../crates/mish/src/forward.rs)):

| Hello | Opened by | The acceptor… |
|-------|-----------|---------------|
| `History` | client | answers a scrollback request |
| `DirectForward { host, port }` | client (`-L`) | **dials** `host:port`, relays |
| `RequestRemoteForward { bind }` | client (`-R`) | **binds** a listener, acks, relays each accept back |
| `ForwardedConnection { bind }` | server (`-R`) | **dials** the client's configured target for `bind`, relays |

`-L` and `-R` are symmetric: whichever side *accepts* a stream is the side that
dials the target. The only asymmetry is who listens — the client for `-L`, the
server for `-R`. After the hello, a data stream is a pure byte relay
(`tokio::io::copy_bidirectional` between the TCP socket and the joined QUIC
stream halves), with half-close propagated in both directions.

A `-R` forward's server-side listener is tied to its control stream: closing it
(you detach, or the connection dies) tears the listener down and frees the port.

### Where it's tested

- [`crates/mish/tests/port_forward.rs`](../crates/mish/tests/port_forward.rs) —
  `-L` and `-R` relay real bytes over real QUIC; `--no-forward` refuses both; the
  client refuses a forwarded connection for an unconfigured bind.
- [`crates/mish/src/forward.rs`](../crates/mish/src/forward.rs) `#[cfg(test)]` —
  spec parsing, codec round-trip + panic-free decode on hostile bytes.
