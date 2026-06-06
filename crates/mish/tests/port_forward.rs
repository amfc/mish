//! End-to-end port forwarding over a real QUIC connection.
//!
//! Each test stands up real loopback QUIC endpoints (the same plumbing the
//! binaries use), real TCP listeners/echo servers, and the actual
//! `mish::forward` tasks — exercising the whole `-L`/`-R` data path, the
//! default-deny refusal (a server without `--allow-forward`), and the
//! client-side security gate that refuses forwarded connections for binds it
//! never requested.

use std::sync::Arc;
use std::time::Duration;

use mish::forward::{
    self, remote_targets, request_remote_forward, run_local_forward, serve_forwarded_connections,
    serve_side_channels, ForwardSpec, StreamHello,
};
use mish_quic::transport::{self, QuicTransport};
use mish_ssp::framing::{read_message, write_message, MAX_MESSAGE_LEN};
use mish_terminal::emulator::Emulator;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const TIMEOUT: Duration = Duration::from_secs(10);

/// Spawn a one-shot TCP echo server on loopback; returns its bound port. It
/// accepts a single connection and echoes everything back until EOF.
async fn echo_server() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    (port, handle)
}

/// Connect a QUIC client to a fresh loopback server and return both transports.
async fn quic_pair() -> (Arc<QuicTransport>, Arc<QuicTransport>) {
    let (server_ep, addr, _cert) = transport::loopback_server().unwrap();
    let accept = tokio::spawn(async move { transport::accept(&server_ep).await.unwrap() });
    let client_ep = transport::loopback_client().unwrap();
    let client = transport::connect(&client_ep, addr, "localhost")
        .await
        .unwrap();
    let server = accept.await.unwrap();
    (Arc::new(client), Arc::new(server))
}

/// `-L`: a local listener on the client tunnels to a target the server dials.
#[tokio::test]
async fn local_forward_relays_bytes() {
    let (target_port, _echo) = echo_server().await;
    let (client_t, server_t) = quic_pair().await;

    // Server: serve side-channels with forwarding enabled.
    let emu = Emulator::shared(80, 24);
    tokio::spawn(serve_side_channels(server_t, emu, true));

    // Client: a -L forward from an ephemeral local port to the echo server.
    let spec = ForwardSpec::parse(&format!("127.0.0.1:0:127.0.0.1:{target_port}"), "127.0.0.1")
        .unwrap();
    let local = run_local_forward(client_t, spec).await.unwrap();

    // Drive bytes through the tunnel and expect them echoed back.
    let mut conn = TcpStream::connect(local).await.unwrap();
    conn.write_all(b"hello tunnel").await.unwrap();
    let mut buf = [0u8; 12];
    tokio::time::timeout(TIMEOUT, conn.read_exact(&mut buf))
        .await
        .expect("a timely echo")
        .expect("read echo");
    assert_eq!(&buf, b"hello tunnel");
}

/// `-R`: the server listens; an inbound connection there is relayed to a target
/// the client dials.
#[tokio::test]
async fn remote_forward_relays_bytes() {
    let (target_port, _echo) = echo_server().await; // client-local target
    let (client_t, server_t) = quic_pair().await;

    let emu = Emulator::shared(80, 24);
    tokio::spawn(serve_side_channels(server_t, emu, true));

    // Client: request a -R forward (server binds ephemeral) to the local echo.
    let spec = ForwardSpec::parse(&format!("127.0.0.1:0:127.0.0.1:{target_port}"), "127.0.0.1")
        .unwrap();
    let targets = remote_targets(std::slice::from_ref(&spec));
    let rf = request_remote_forward(&client_t, &spec).await.unwrap();
    assert!(rf.bound_port != 0, "server reported its bound port");
    tokio::spawn(serve_forwarded_connections(client_t.clone(), targets));

    // Connect to the *server-side* listener and expect the bytes echoed by the
    // client-local target through the reverse tunnel.
    let mut conn = TcpStream::connect(("127.0.0.1", rf.bound_port)).await.unwrap();
    conn.write_all(b"reverse!").await.unwrap();
    let mut buf = [0u8; 8];
    tokio::time::timeout(TIMEOUT, conn.read_exact(&mut buf))
        .await
        .expect("a timely echo")
        .expect("read echo");
    assert_eq!(&buf, b"reverse!");

    drop(rf); // tearing down the forward closes the listener
}

/// Default deny (a server without `--allow-forward`): it refuses `-L` (the
/// tunnel stream is closed with no data relayed) and `-R` (the request is NAK'd).
#[tokio::test]
async fn disabled_forwarding_is_refused() {
    let (target_port, _echo) = echo_server().await;
    let (client_t, server_t) = quic_pair().await;

    // Forwarding not enabled on the server (the default).
    let emu = Emulator::shared(80, 24);
    tokio::spawn(serve_side_channels(server_t, emu, false));

    // -L: the listener still binds locally, but the server refuses the stream,
    // so a connection through it gets EOF with no echo.
    let spec = ForwardSpec::parse(&format!("127.0.0.1:0:127.0.0.1:{target_port}"), "127.0.0.1")
        .unwrap();
    let local = run_local_forward(client_t.clone(), spec).await.unwrap();
    let mut conn = TcpStream::connect(local).await.unwrap();
    let _ = conn.write_all(b"nope").await;
    let mut buf = Vec::new();
    let n = tokio::time::timeout(TIMEOUT, conn.read_to_end(&mut buf))
        .await
        .expect("the refused tunnel closes promptly")
        .unwrap_or(0);
    assert_eq!(n, 0, "no bytes should be echoed when forwarding is disabled");

    // -R: the request is refused with an error ack.
    let rspec = ForwardSpec::parse("127.0.0.1:0:127.0.0.1:1", "127.0.0.1").unwrap();
    let err = request_remote_forward(&client_t, &rspec).await.unwrap_err();
    assert!(
        err.to_string().contains("refused") || err.to_string().contains("disabled"),
        "expected a refusal, got {err}"
    );
}

/// Security gate: a hostile server that opens a `ForwardedConnection` for a bind
/// the client never configured must be refused — the client never dials.
#[tokio::test]
async fn client_refuses_unconfigured_forwarded_connection() {
    let (target_port, echo) = echo_server().await;
    let (client_t, server_t) = quic_pair().await;

    // Client accept loop with an EMPTY target map: nothing is configured.
    tokio::spawn(serve_forwarded_connections(client_t, forward::RemoteTargets::new()));

    // "Hostile server": open a stream claiming a forwarded connection for a bind
    // the client never asked for, pointing at the echo server.
    let (mut send, mut recv) = server_t.open_side_channel().await.unwrap();
    let hello = StreamHello::ForwardedConnection {
        bind_host: "127.0.0.1".into(),
        bind_port: target_port, // arbitrary; not in the (empty) client map
    };
    write_message(&mut send, &hello.encode()).await.unwrap();
    let _ = send.write_all(b"payload").await;

    // The client refuses and drops the stream: our recv half sees a clean EOF
    // (no relay, no response), and the echo server gets no connection.
    let got = tokio::time::timeout(TIMEOUT, read_message(&mut recv, MAX_MESSAGE_LEN))
        .await
        .expect("the refused stream resolves promptly");
    assert!(
        matches!(got, Ok(None) | Err(_)),
        "client must not relay an unconfigured forwarded connection"
    );

    // Belt and suspenders: the echo target never accepted a connection. (If the
    // client had wrongly dialed it, the echo task would have served it; we can't
    // easily assert a negative directly, so rely on the closed stream above and
    // that no echo bytes ever came back.)
    echo.abort();
}
