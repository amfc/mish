//! Port forwarding over QUIC streams — `ssh -L` / `-R`-style TCP tunnels.
//!
//! mosh's hand-rolled UDP/OCB transport has no reliable multiplexed channel, so
//! upstream mosh cannot forward ports at all. Our QUIC connection already carries
//! reliable **side-channels** (see [`crate::scrollback`] and
//! [`mish_ssp::framing`]); this module reuses that exact primitive to turn each
//! forwarded TCP connection into one **bidirectional QUIC stream**, multiplexed
//! over the *same* mutually-authenticated connection. QUIC owns reliability,
//! ordering, flow control, and per-stream congestion — so once a stream exists
//! the relay is pure byte-shoveling.
//!
//! ## Stream protocol
//!
//! Every side-channel stream now opens with a framed [`StreamHello`] tag, so a
//! single accept loop can demultiplex history, `-L`, and `-R` traffic. After the
//! hello, a *data* stream (`-L`/`-R`) carries raw forwarded bytes; a *control*
//! exchange (history, `-R` setup) carries further framed messages.
//!
//! | Hello | Opener | Acceptor does |
//! |-------|--------|---------------|
//! | [`StreamHello::History`] | client | answers a scrollback request |
//! | [`StreamHello::DirectForward`] | client (`-L`) | **dials** `host:port`, relays |
//! | [`StreamHello::RequestRemoteForward`] | client (`-R`) | **binds** a listener, relays each accept back |
//! | [`StreamHello::ForwardedConnection`] | server (`-R`) | **dials** the client's configured target, relays |
//!
//! `-L` and `-R` are symmetric: the side that *accepts* the stream is the side
//! that dials the target. The only asymmetry is *who listens* — the client for
//! `-L`, the server for `-R` (which the client must request first).
//!
//! ## Security
//!
//! Forwarding is **off until explicitly requested** per-forward (`-L`/`-R`
//! flags); see [`SECURITY.md`](../../../SECURITY.md). The connection is already
//! mutually authenticated, so the peer is the SSH-authenticated owner. The one
//! genuinely new surface is a *malicious server* reaching back into the client's
//! localhost via `-R`: the client therefore **only dials targets it explicitly
//! configured**, refusing any [`StreamHello::ForwardedConnection`] for a bind it
//! never requested. The server can hard-disable all forwarding (`--no-forward`).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use mish_quic::transport::QuicTransport;
use mish_quic::{RecvStream, SendStream};
use mish_ssp::framing::{read_message, write_message, MAX_MESSAGE_LEN};
use mish_terminal::emulator::Emulator;
use serde::{Deserialize, Serialize};
use tokio::net::{TcpListener, TcpStream};

/// A DNS name is at most 253 characters; reject anything longer as a target host
/// so a forged/oversized hello can't drive an absurd resolver request. The
/// framing cap already bounds the message; this bounds the dial.
const MAX_HOST_LEN: usize = 255;

/// The first framed message on every side-channel stream, tagging what the stream
/// carries so one accept loop can demultiplex it. Encoded with the same
/// length-prefixed framing as the payload that follows.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum StreamHello {
    /// A scrollback history request/response exchange (see [`crate::scrollback`]).
    /// The [`mish_terminal::history::HistoryRequest`] follows as the next frame.
    History,
    /// `-L` data stream: the client accepted a local connection; the **server**
    /// must dial `host:port` and relay raw bytes both ways.
    DirectForward { host: String, port: u16 },
    /// `-R` control stream: the client asks the **server** to listen on
    /// `bind_host:bind_port` and relay each accepted connection back. The server
    /// replies with a [`ForwardAck`]; the stream then stays open for the lifetime
    /// of the forward (closing it tears the listener down).
    RequestRemoteForward { bind_host: String, bind_port: u16 },
    /// `-R` data stream: the server accepted a connection on a remote-forward
    /// listener; the **client** maps `bind_host:bind_port` back to the target it
    /// configured for that `-R` and dials it. Carries the *requested* bind
    /// identity (so an ephemeral `bind_port == 0` still keys the client's map).
    ForwardedConnection { bind_host: String, bind_port: u16 },
}

impl StreamHello {
    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).expect("StreamHello serialization is infallible")
    }
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        bincode::deserialize(bytes).ok()
    }
}

/// The server's reply to a [`StreamHello::RequestRemoteForward`].
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ForwardAck {
    /// Whether the listener was bound (forwarding enabled + bind succeeded).
    pub ok: bool,
    /// The port actually bound (echoing back the ephemeral port when 0 was asked).
    pub bound_port: u16,
    /// A human-readable reason when `!ok` (forwarding disabled, address in use…).
    pub message: String,
}

impl ForwardAck {
    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).expect("ForwardAck serialization is infallible")
    }
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        bincode::deserialize(bytes).ok()
    }
}

/// A parsed `-L`/`-R` forward specification (`[bind:]port:host:hostport`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardSpec {
    /// Address to bind the listener on (client side for `-L`, server side for
    /// `-R`). Defaults to loopback when the spec omits it.
    pub bind_host: String,
    /// Port to listen on. `0` requests an ephemeral port.
    pub bind_port: u16,
    /// Host the *accepting* side dials (the remote target for `-L`, a
    /// client-local target for `-R`).
    pub target_host: String,
    /// Port the accepting side dials.
    pub target_port: u16,
}

impl ForwardSpec {
    /// Parse an ssh-style forward spec: `[bind_address:]port:host:hostport`.
    ///
    /// With no `bind_address`, the listener binds `default_bind` (loopback, as
    /// ssh does without `GatewayPorts`). IPv6 literals (which contain colons)
    /// aren't supported in v1 — use a hostname or IPv4 literal.
    pub fn parse(spec: &str, default_bind: &str) -> Result<Self, String> {
        let parts: Vec<&str> = spec.split(':').collect();
        let parse_port = |s: &str| -> Result<u16, String> {
            s.parse::<u16>().map_err(|_| format!("invalid port {s:?} in forward spec {spec:?}"))
        };
        let (bind_host, bind_port, target_host, target_port) = match parts.as_slice() {
            [bind, port, host, hostport] => (
                (*bind).to_string(),
                parse_port(port)?,
                (*host).to_string(),
                parse_port(hostport)?,
            ),
            [port, host, hostport] => (
                default_bind.to_string(),
                parse_port(port)?,
                (*host).to_string(),
                parse_port(hostport)?,
            ),
            _ => {
                return Err(format!(
                    "forward spec {spec:?} must be [bind:]port:host:hostport \
                     (IPv6 literals unsupported)"
                ))
            }
        };
        if target_host.is_empty() {
            return Err(format!("forward spec {spec:?} has an empty target host"));
        }
        Ok(ForwardSpec {
            bind_host,
            bind_port,
            target_host,
            target_port,
        })
    }
}

/// Relay bytes bidirectionally between a local TCP connection and a QUIC
/// bidirectional stream until either side closes. Pure byte shovel — QUIC
/// provides reliability, ordering, and flow control. Joining the QUIC recv/send
/// halves into one duplex lets [`tokio::io::copy_bidirectional`] propagate
/// half-close in both directions (EOF on one side shuts down the other's write).
async fn relay(mut tcp: TcpStream, send: SendStream, recv: RecvStream) {
    let mut quic = tokio::io::join(recv, send);
    let _ = tokio::io::copy_bidirectional(&mut tcp, &mut quic).await;
}

/// Reject a target host that is empty or implausibly long before we hand it to
/// the resolver. Returns the `host:port` dial string when acceptable.
fn dial_target(host: &str, port: u16) -> Option<String> {
    if host.is_empty() || host.len() > MAX_HOST_LEN {
        return None;
    }
    Some(format!("{host}:{port}"))
}

// ───────────────────────────── server side ──────────────────────────────────

/// Accept side-channel streams on `transport` and demultiplex each by its
/// [`StreamHello`]: scrollback history is always served; `-L`/`-R` forwarding is
/// served only when `forward` is enabled (`mish-server` without `--no-forward`).
/// Runs until the connection goes away. Replaces the history-only accept loop.
pub async fn serve_side_channels(
    transport: Arc<QuicTransport>,
    emu: Arc<Mutex<Emulator>>,
    forward: bool,
) {
    loop {
        let (send, recv) = match transport.accept_side_channel().await {
            Ok(s) => s,
            Err(_) => return, // connection closed / gone
        };
        let emu = emu.clone();
        let transport = transport.clone();
        tokio::spawn(async move {
            dispatch_server_stream(transport, send, recv, emu, forward).await;
        });
    }
}

/// Read the [`StreamHello`] off a freshly-accepted server-side stream and route
/// it. Unknown/forged hellos and disabled forwarding are dropped quietly (the
/// peer is authenticated, but defensive).
async fn dispatch_server_stream(
    transport: Arc<QuicTransport>,
    mut send: SendStream,
    mut recv: RecvStream,
    emu: Arc<Mutex<Emulator>>,
    forward: bool,
) {
    let hello = match read_message(&mut recv, MAX_MESSAGE_LEN).await {
        Ok(Some(b)) => match StreamHello::decode(&b) {
            Some(h) => h,
            None => return,
        },
        _ => return, // empty / malformed framing
    };
    match hello {
        StreamHello::History => {
            crate::scrollback::serve_one(send, recv, emu).await;
        }
        StreamHello::DirectForward { host, port } => {
            if !forward {
                tracing::warn!(target: "mish::forward", %host, port, "refusing -L: forwarding disabled");
                return;
            }
            handle_direct_forward(send, recv, host, port).await;
        }
        StreamHello::RequestRemoteForward {
            bind_host,
            bind_port,
        } => {
            if !forward {
                tracing::warn!(target: "mish::forward", %bind_host, bind_port, "refusing -R: forwarding disabled");
                let ack = ForwardAck {
                    ok: false,
                    bound_port: 0,
                    message: "port forwarding is disabled on the server (--no-forward)".into(),
                };
                let _ = write_message(&mut send, &ack.encode()).await;
                let _ = send.finish();
                return;
            }
            handle_remote_forward_request(transport, send, recv, bind_host, bind_port).await;
        }
        // The server is never the side that accepts a forwarded connection.
        StreamHello::ForwardedConnection { .. } => {
            tracing::warn!(target: "mish::forward", "server received an unexpected ForwardedConnection hello");
        }
    }
}

/// Server side of `-L`: dial the client-requested `host:port` and relay the
/// stream to it. The hello frame is already consumed; the rest of the stream is
/// raw forwarded bytes.
async fn handle_direct_forward(send: SendStream, recv: RecvStream, host: String, port: u16) {
    let Some(target) = dial_target(&host, port) else {
        tracing::warn!(target: "mish::forward", %host, port, "refusing -L: implausible target host");
        return;
    };
    match TcpStream::connect(&target).await {
        Ok(tcp) => {
            tracing::info!(target: "mish::forward", %target, "-L connection established");
            relay(tcp, send, recv).await;
        }
        Err(e) => tracing::warn!(target: "mish::forward", %target, error = %e, "-L dial failed"),
    }
}

/// Server side of `-R`: bind a listener on `bind_host:bind_port`, ack the bound
/// port, then open a fresh `ForwardedConnection` stream back to the client for
/// each accepted connection. The listener lives until the control stream closes
/// (the client tore the forward down, or the connection died) — read EOF on
/// `recv` is the teardown signal, so a dead connection frees the port promptly.
async fn handle_remote_forward_request(
    transport: Arc<QuicTransport>,
    mut send: SendStream,
    mut recv: RecvStream,
    bind_host: String,
    bind_port: u16,
) {
    let listener = match TcpListener::bind((bind_host.as_str(), bind_port)).await {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!(target: "mish::forward", %bind_host, bind_port, error = %e, "-R bind failed");
            let ack = ForwardAck {
                ok: false,
                bound_port: 0,
                message: format!("could not bind {bind_host}:{bind_port}: {e}"),
            };
            let _ = write_message(&mut send, &ack.encode()).await;
            let _ = send.finish();
            return;
        }
    };
    let bound_port = listener.local_addr().map(|a| a.port()).unwrap_or(bind_port);
    let ack = ForwardAck {
        ok: true,
        bound_port,
        message: String::new(),
    };
    if write_message(&mut send, &ack.encode()).await.is_err() {
        return;
    }
    tracing::info!(target: "mish::forward", %bind_host, bound_port, "-R listening");

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let tcp = match accepted {
                    Ok((tcp, _peer)) => tcp,
                    Err(_) => break,
                };
                let transport = transport.clone();
                // The hello echoes the *requested* bind identity so the client
                // can key its target map (even for an ephemeral bind_port == 0).
                let hello = StreamHello::ForwardedConnection {
                    bind_host: bind_host.clone(),
                    bind_port,
                };
                tokio::spawn(async move {
                    let (mut s, r) = match transport.open_side_channel().await {
                        Ok(v) => v,
                        Err(_) => return, // connection gone
                    };
                    if write_message(&mut s, &hello.encode()).await.is_err() {
                        return;
                    }
                    relay(tcp, s, r).await;
                });
            }
            // Control-stream liveness: a clean EOF (forward torn down) or any
            // error (connection died) ends the listener and frees the port.
            r = read_message(&mut recv, MAX_MESSAGE_LEN) => {
                match r {
                    Ok(Some(_)) => continue, // unexpected extra frame: ignore, keep serving
                    _ => break,
                }
            }
        }
    }
    tracing::info!(target: "mish::forward", %bind_host, bound_port, "-R listener closed");
}

// ───────────────────────────── client side ──────────────────────────────────

/// Client side of `-L`: bind a local listener and, for each accepted connection,
/// open a [`StreamHello::DirectForward`] stream so the server dials the target
/// and relays. Binds synchronously (so a port clash surfaces to the caller) and
/// spawns the accept loop. Returns the bound local address.
pub async fn run_local_forward(
    transport: Arc<QuicTransport>,
    spec: ForwardSpec,
) -> std::io::Result<SocketAddr> {
    let listener = TcpListener::bind((spec.bind_host.as_str(), spec.bind_port)).await?;
    let local = listener.local_addr()?;
    tracing::info!(target: "mish::forward", %local, target_host = %spec.target_host, target_port = spec.target_port, "-L listening");
    tokio::spawn(async move {
        loop {
            let tcp = match listener.accept().await {
                Ok((tcp, _peer)) => tcp,
                Err(_) => break,
            };
            let transport = transport.clone();
            let hello = StreamHello::DirectForward {
                host: spec.target_host.clone(),
                port: spec.target_port,
            };
            tokio::spawn(async move {
                let (mut s, r) = match transport.open_side_channel().await {
                    Ok(v) => v,
                    Err(_) => return,
                };
                if write_message(&mut s, &hello.encode()).await.is_err() {
                    return;
                }
                relay(tcp, s, r).await;
            });
        }
    });
    Ok(local)
}

/// A live `-R` remote-forward registration. Holding it keeps the server's
/// listener open (the control stream stays open); dropping it tears the forward
/// down. The session keeps these alive for its lifetime.
pub struct RemoteForward {
    /// The server-side port actually bound (useful when an ephemeral port was
    /// requested).
    pub bound_port: u16,
    // The control stream halves; kept alive so the server's listener persists.
    _send: SendStream,
    _recv: RecvStream,
}

/// Client side of `-R`: ask the server to bind a listener and wait for its ack.
/// On success returns a [`RemoteForward`] the caller must keep alive for the
/// forward to persist. The matching client-local targets must already be
/// registered with [`serve_forwarded_connections`].
pub async fn request_remote_forward(
    transport: &QuicTransport,
    spec: &ForwardSpec,
) -> std::io::Result<RemoteForward> {
    let (mut send, mut recv) = transport
        .open_side_channel()
        .await
        .map_err(std::io::Error::other)?;
    let hello = StreamHello::RequestRemoteForward {
        bind_host: spec.bind_host.clone(),
        bind_port: spec.bind_port,
    };
    write_message(&mut send, &hello.encode()).await?;
    let ack = match read_message(&mut recv, MAX_MESSAGE_LEN).await? {
        Some(b) => ForwardAck::decode(&b)
            .ok_or_else(|| std::io::Error::other("malformed -R ack from server"))?,
        None => return Err(std::io::Error::other("server closed the -R control stream")),
    };
    if !ack.ok {
        return Err(std::io::Error::other(format!(
            "server refused -R {}:{}: {}",
            spec.bind_host, spec.bind_port, ack.message
        )));
    }
    Ok(RemoteForward {
        bound_port: ack.bound_port,
        _send: send,
        _recv: recv,
    })
}

/// Map from a requested `-R` bind identity to the client-local target to dial.
pub type RemoteTargets = HashMap<(String, u16), (String, u16)>;

/// Build the [`RemoteTargets`] map from the configured `-R` specs, keyed by the
/// *requested* bind identity (matching the hello the server echoes back).
pub fn remote_targets(specs: &[ForwardSpec]) -> RemoteTargets {
    specs
        .iter()
        .map(|s| {
            (
                (s.bind_host.clone(), s.bind_port),
                (s.target_host.clone(), s.target_port),
            )
        })
        .collect()
}

/// Client side of `-R` data: accept server-opened streams and, for each
/// [`StreamHello::ForwardedConnection`], dial the client-local target the user
/// configured for that bind and relay. **Security gate:** a connection for a
/// bind the client never requested is refused (a malicious server cannot use
/// `-R` to reach arbitrary client-local addresses). Runs until the connection
/// goes away. Only spawn this when at least one `-R` is configured.
pub async fn serve_forwarded_connections(transport: Arc<QuicTransport>, targets: RemoteTargets) {
    let targets = Arc::new(targets);
    loop {
        let (send, recv) = match transport.accept_side_channel().await {
            Ok(s) => s,
            Err(_) => return,
        };
        let targets = targets.clone();
        tokio::spawn(async move {
            handle_forwarded_connection(send, recv, &targets).await;
        });
    }
}

async fn handle_forwarded_connection(
    send: SendStream,
    mut recv: RecvStream,
    targets: &RemoteTargets,
) {
    let hello = match read_message(&mut recv, MAX_MESSAGE_LEN).await {
        Ok(Some(b)) => match StreamHello::decode(&b) {
            Some(h) => h,
            None => return,
        },
        _ => return,
    };
    let StreamHello::ForwardedConnection {
        bind_host,
        bind_port,
    } = hello
    else {
        tracing::warn!(target: "mish::forward", "client refused an unexpected side-channel hello from the server");
        return;
    };
    // SECURITY: only dial a target the user explicitly configured with `-R`.
    let Some((host, port)) = targets.get(&(bind_host.clone(), bind_port)).cloned() else {
        tracing::warn!(
            target: "mish::forward",
            %bind_host, bind_port,
            "refusing forwarded connection for an unconfigured -R bind (possible hostile server)"
        );
        return;
    };
    let Some(target) = dial_target(&host, port) else {
        return;
    };
    match TcpStream::connect(&target).await {
        Ok(tcp) => {
            tracing::info!(target: "mish::forward", %target, "-R connection established");
            relay(tcp, send, recv).await;
        }
        Err(e) => tracing::warn!(target: "mish::forward", %target, error = %e, "-R target dial failed"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_four_part_spec() {
        let s = ForwardSpec::parse("0.0.0.0:8080:example.com:80", "127.0.0.1").unwrap();
        assert_eq!(
            s,
            ForwardSpec {
                bind_host: "0.0.0.0".into(),
                bind_port: 8080,
                target_host: "example.com".into(),
                target_port: 80,
            }
        );
    }

    #[test]
    fn three_part_spec_uses_default_bind() {
        let s = ForwardSpec::parse("8080:localhost:3000", "127.0.0.1").unwrap();
        assert_eq!(
            s,
            ForwardSpec {
                bind_host: "127.0.0.1".into(),
                bind_port: 8080,
                target_host: "localhost".into(),
                target_port: 3000,
            }
        );
    }

    #[test]
    fn rejects_bad_specs() {
        // Too few fields.
        assert!(ForwardSpec::parse("8080:localhost", "127.0.0.1").is_err());
        // Non-numeric port.
        assert!(ForwardSpec::parse("notaport:localhost:80", "127.0.0.1").is_err());
        // Port out of range.
        assert!(ForwardSpec::parse("99999:localhost:80", "127.0.0.1").is_err());
        // Empty target host.
        assert!(ForwardSpec::parse("8080::80", "127.0.0.1").is_err());
        // Five fields (e.g. an IPv6 literal) is unsupported.
        assert!(ForwardSpec::parse("::1:80:host:80", "127.0.0.1").is_err());
    }

    #[test]
    fn stream_hello_round_trips() {
        for h in [
            StreamHello::History,
            StreamHello::DirectForward {
                host: "host".into(),
                port: 22,
            },
            StreamHello::RequestRemoteForward {
                bind_host: "127.0.0.1".into(),
                bind_port: 0,
            },
            StreamHello::ForwardedConnection {
                bind_host: "0.0.0.0".into(),
                bind_port: 9000,
            },
        ] {
            assert_eq!(StreamHello::decode(&h.encode()), Some(h));
        }
    }

    #[test]
    fn forward_ack_round_trips() {
        let ack = ForwardAck {
            ok: true,
            bound_port: 4242,
            message: String::new(),
        };
        assert_eq!(ForwardAck::decode(&ack.encode()), Some(ack));
    }

    #[test]
    fn decode_is_panic_free_on_garbage() {
        // Hostile/truncated bytes must never panic — just fail to decode.
        for bytes in [
            &b""[..],
            &b"\x00"[..],
            &b"\xff\xff\xff\xff"[..],
            &[0xAB; 64][..],
        ] {
            let _ = StreamHello::decode(bytes);
            let _ = ForwardAck::decode(bytes);
        }
    }

    #[test]
    fn dial_target_bounds_host() {
        assert_eq!(dial_target("h", 80), Some("h:80".into()));
        assert!(dial_target("", 80).is_none());
        assert!(dial_target(&"x".repeat(MAX_HOST_LEN + 1), 80).is_none());
    }

    #[test]
    fn remote_targets_keyed_by_requested_bind() {
        let specs = vec![
            ForwardSpec::parse("9000:localhost:3000", "127.0.0.1").unwrap(),
            ForwardSpec::parse("0.0.0.0:0:db:5432", "127.0.0.1").unwrap(),
        ];
        let map = remote_targets(&specs);
        assert_eq!(
            map.get(&("127.0.0.1".into(), 9000)),
            Some(&("localhost".into(), 3000))
        );
        assert_eq!(
            map.get(&("0.0.0.0".into(), 0)),
            Some(&("db".into(), 5432))
        );
    }
}
