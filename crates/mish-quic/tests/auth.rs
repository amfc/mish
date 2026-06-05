//! Mutual-authentication security tests for the QUIC transport.
//!
//! The threat these guard against: without client authentication, anyone who can
//! reach the server's UDP port could inject keystrokes into the SSH-authenticated
//! user's shell. `authenticated_server_config` mints a per-session client cert
//! that is delivered only over the SSH-authenticated channel and pins it, so only
//! a peer holding that cert/key can connect.
//!
//! Positive: a client with the minted credentials connects and exchanges a
//! datagram. Negatives (the security assertions): a client presenting no client
//! cert, the wrong client cert, or trusting the wrong *server* cert is rejected
//! and no data flows.

use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use mish_quic::transport::{self, QuicTransport};
use mish_ssp::transport::Transport;
use quinn::Endpoint;
use tokio::time::timeout;

/// Accept one connection and echo every datagram back, until it closes.
async fn echo_server(ep: Endpoint) {
    if let Ok(t) = transport::accept(&ep).await {
        while let Ok(bytes) = t.recv().await {
            let _ = t.send(bytes).await;
        }
    }
}

/// Try to establish a session over `client_ep` to `addr` and round-trip one
/// datagram. Returns `true` only if the connection authenticated *and* a datagram
/// echoed back — i.e. the peer is genuinely talking to us. Resends to tolerate an
/// initial pre-negotiation datagram drop.
async fn session_works(client_ep: &Endpoint, addr: SocketAddr) -> bool {
    let conn = match transport::connect(client_ep, addr, "localhost").await {
        Ok(t) => t,
        Err(_) => return false, // handshake rejected → auth failure
    };
    round_trip(&conn).await
}

async fn round_trip(t: &QuicTransport) -> bool {
    let got = timeout(Duration::from_secs(3), async {
        loop {
            // Best-effort resend until the echo comes back (or the outer timeout).
            let _ = t.send(Bytes::from_static(b"ping")).await;
            match timeout(Duration::from_millis(150), t.recv()).await {
                Ok(Ok(b)) if b.as_ref() == b"ping" => return true,
                Ok(Err(_)) => return false, // connection died
                _ => continue,
            }
        }
    })
    .await;
    matches!(got, Ok(true))
}

/// A client holding the minted credentials is accepted and data flows.
#[tokio::test]
async fn authenticated_client_is_accepted() {
    let (server_ep, addr, auth) = transport::loopback_authenticated_server().unwrap();
    let task = tokio::spawn(echo_server(server_ep));

    let client_ep = transport::authenticated_client_endpoint(
        "127.0.0.1:0".parse().unwrap(),
        &auth.server_cert_der,
        &auth.client_cert_der,
        &auth.client_key_der,
    )
    .unwrap();

    assert!(
        session_works(&client_ep, addr).await,
        "client with the minted credentials must be accepted"
    );
    task.abort();
}

/// A client presenting **no** client certificate is rejected (the original gap).
#[tokio::test]
async fn unauthenticated_client_is_rejected() {
    let (server_ep, addr, _auth) = transport::loopback_authenticated_server().unwrap();
    let task = tokio::spawn(echo_server(server_ep));

    // loopback_client uses the insecure config with no client auth.
    let client_ep = transport::loopback_client().unwrap();
    assert!(
        !session_works(&client_ep, addr).await,
        "a client with no certificate must NOT be able to inject datagrams"
    );
    task.abort();
}

/// A client presenting the **wrong** client certificate (from a different
/// session) is rejected.
#[tokio::test]
async fn wrong_client_cert_is_rejected() {
    let (server_ep, addr, auth) = transport::loopback_authenticated_server().unwrap();
    let task = tokio::spawn(echo_server(server_ep));

    // A second, unrelated session's client credentials.
    let (_other_ep, _other_addr, other) = transport::loopback_authenticated_server().unwrap();

    let client_ep = transport::authenticated_client_endpoint(
        "127.0.0.1:0".parse().unwrap(),
        &auth.server_cert_der, // correct server cert (so it's the cert, not the server, under test)
        &other.client_cert_der, // WRONG client cert
        &other.client_key_der,
    )
    .unwrap();

    assert!(
        !session_works(&client_ep, addr).await,
        "a client presenting an unrecognized certificate must be rejected"
    );
    task.abort();
}

/// A client that trusts the **wrong server** cert rejects the real server —
/// protecting against server impersonation / MITM on the UDP path.
#[tokio::test]
async fn wrong_server_cert_rejected_by_client() {
    let (server_ep, addr, auth) = transport::loopback_authenticated_server().unwrap();
    let task = tokio::spawn(echo_server(server_ep));

    let (_other_ep, _other_addr, other) = transport::loopback_authenticated_server().unwrap();

    let client_ep = transport::authenticated_client_endpoint(
        "127.0.0.1:0".parse().unwrap(),
        &other.server_cert_der, // WRONG server cert pinned
        &auth.client_cert_der,  // correct client creds
        &auth.client_key_der,
    )
    .unwrap();

    assert!(
        !session_works(&client_ep, addr).await,
        "client must reject a server whose cert it does not trust"
    );
    task.abort();
}
