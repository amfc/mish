//! End-to-end mutual-auth *negative* tests against the real `mish-server`
//! binary. `mish-quic/tests/auth.rs` proves the config rejects bad clients in
//! isolation; these prove the actual server process (which must be using
//! `authenticated_server_config`) does too — and that a client rejects a server
//! whose cert it doesn't trust (MITM protection). Without these, a regression
//! that wired the binary to a no-client-auth config would pass auth.rs.

use std::time::Duration;

use mish::bootstrap;
use mish_quic::transport;

/// Spawn the real server via the local bootstrap and return the connection info.
async fn spawn_server() -> bootstrap::Bootstrap {
    let server = env!("CARGO_BIN_EXE_mish-server");
    bootstrap::local(server, false, None, Some("/bin/sh"))
        .await
        .expect("bootstrap should start the server and print MISH CONNECT")
}

/// A client presenting **no** client certificate is rejected by the real server.
/// (With TLS 1.3, the client-side `connect` can complete before the server's
/// mandatory-client-auth rejection arrives, so we assert the connection then gets
/// *closed* by the server rather than relying on `connect` itself failing.)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_server_rejects_unauthenticated_client() {
    let boot = spawn_server().await;
    // The insecure client config presents no client cert.
    let ep = transport::insecure_client_endpoint("0.0.0.0:0".parse().unwrap()).unwrap();
    // If `connect` itself fails, the handshake was rejected — fine. If it
    // completes client-side, the server must then reject + close the connection
    // (a legitimate client's connection would stay open and deliver the initial
    // screen).
    if let Ok(Ok(conn)) = tokio::time::timeout(
        Duration::from_secs(10),
        transport::connect(&ep, boot.addr, "localhost"),
    )
    .await
    {
        let closed = tokio::time::timeout(Duration::from_secs(8), conn.connection().closed()).await;
        assert!(
            closed.is_ok(),
            "server must close (reject) an unauthenticated client's connection"
        );
    }
    drop(boot);
}

/// A client that pins the **wrong server cert** rejects the real server (so a
/// MITM presenting a different cert on the UDP path can't impersonate it), even
/// while presenting the correct client credentials.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_client_rejects_wrong_server_cert() {
    let boot = spawn_server().await;
    // A bogus server cert from an unrelated session.
    let (_cfg, bogus) = mish_quic::config::authenticated_server_config();
    let ep = transport::authenticated_client_endpoint(
        "0.0.0.0:0".parse().unwrap(),
        &bogus.server_cert_der, // WRONG server cert pinned
        &boot.client_cert_der,  // correct client credentials
        &boot.client_key_der,
    )
    .unwrap();
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        transport::connect(&ep, boot.addr, "localhost"),
    )
    .await;
    assert!(
        matches!(result, Ok(Err(_)) | Err(_)),
        "client must reject a server whose certificate it does not trust"
    );
    drop(boot);
}
