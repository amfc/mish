//! Regression test for the unauthenticated-handshake DoS (audit finding H1).
//!
//! `quinn::Endpoint::accept()` yields an `Incoming` as soon as a QUIC Initial
//! arrives — *before* the pinned-client-cert check — and `transport::accept`
//! drives the handshake, so it returns `Err` for any peer that reaches the UDP
//! port without the minted client credentials. The server's persistent/shared
//! session loops used to propagate that error with `?`, so a single
//! unauthenticated handshake from *any* QUIC speaker tore down the live session
//! of the legitimately-attached user — a remote, credential-less DoS against
//! exactly the user the threat model prioritizes.
//!
//! The fix routes every session-accept site through `accept_authenticated`, which
//! logs-and-skips a failed handshake and only treats a closed endpoint as fatal.
//! This test exercises the real `mish-server` binary in `--shared` mode (which
//! implies `--persist`, putting the server in the vulnerable accept loop): it
//! drives a genuine SSP session, fires a burst of unauthenticated handshakes at
//! the port, then proves the session is *still functionally alive* by typing a
//! command and seeing the shell echo it back. Before the fix the server process
//! exits and the post-attack round-trip never completes; this test fails.
//!
//! (We assert liveness by round-trip, not by `connection().closed()`: a killed
//! server process never sends a CONNECTION_CLOSE, so the client's connection
//! lingers until its idle timeout — `closed()` would not catch the death.)

use std::sync::Arc;
use std::time::Duration;

use mish::bootstrap;
use mish_quic::transport::{self, QuicTransport};
use mish_ssp::clock::{Clock, SystemClock};
use mish_ssp::core::SspConfig;
use mish_ssp::session::{Driver, Session, SessionHandle};
use mish_terminal::screen::Screen;
use mish_terminal::user::UserStream;
use tokio::sync::watch;

/// Spawn the real server via the local bootstrap in shared/persistent mode and
/// return its connection info.
async fn spawn_shared_server() -> bootstrap::Bootstrap {
    let server = env!("CARGO_BIN_EXE_mish-server");
    bootstrap::local(
        server,
        /* shared = */ true,
        /* forward = */ false,
        None,
        Some("/bin/sh"),
    )
    .await
    .expect("bootstrap should start the shared server and print MISH CONNECT")
}

/// A minimal real client: an SSP `Driver` over the QUIC transport that can type
/// and observe the synced server screen — the same machinery `mish-client` uses.
struct Client {
    stream: UserStream,
    handle: SessionHandle<UserStream, Screen>,
    remote: watch::Receiver<Screen>,
}

impl Client {
    fn spawn(conn: QuicTransport, clock: Arc<dyn Clock>) -> Self {
        let (driver, handle) = Driver::<QuicTransport, UserStream, Screen>::with(
            Arc::new(conn),
            clock,
            SspConfig::default(),
        );
        driver.spawn();
        let mut stream = UserStream::new();
        stream.push_resize(80, 24); // report geometry so the server has a remote state
        handle.set_local(stream.clone());
        let remote = handle.subscribe_remote();
        Self {
            stream,
            handle,
            remote,
        }
    }

    fn type_str(&mut self, s: &str) {
        self.stream.push_keystroke(s.as_bytes().to_vec());
        self.handle.set_local(self.stream.clone());
    }

    /// Wait until the synced screen contains `needle`, panicking on timeout.
    async fn expect_contains(&mut self, needle: &str) {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if self.remote.borrow_and_update().to_text().contains(needle) {
                    return;
                }
                if self.remote.changed().await.is_err() {
                    panic!("client remote closed before seeing {needle:?}");
                }
            }
        })
        .await
        .unwrap_or_else(|_| panic!("client never saw {needle:?} (session not alive)"));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unauthenticated_handshake_does_not_kill_live_session() {
    let boot = spawn_shared_server().await;
    let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());

    // A legitimate client attaches with the minted credentials and drives a real
    // SSP session.
    let client_ep = transport::authenticated_client_endpoint(
        "0.0.0.0:0".parse().unwrap(),
        &boot.server_cert_der,
        &boot.client_cert_der,
        &boot.client_key_der,
    )
    .unwrap();
    let conn = tokio::time::timeout(
        Duration::from_secs(10),
        transport::connect(&client_ep, boot.addr, "localhost"),
    )
    .await
    .expect("legit client connect timed out")
    .expect("legit client with the minted credentials must connect");
    let mut client = Client::spawn(conn, clock);

    // Baseline: the session is genuinely live — the shell echoes a typed command.
    client.type_str("echo zzPRE\r");
    client.expect_contains("zzPRE").await;

    // The attack: a burst of peers that reach the UDP port but fail the
    // mutual-TLS handshake (the insecure client config presents no client cert).
    // Each makes the server's accept arm fire and the handshake fail. Pre-fix, the
    // first such error propagated out of `serve_shared` via `?` and ended the whole
    // session (the server process exits); post-fix it is logged and skipped.
    for _ in 0..5 {
        let junk_ep = transport::insecure_client_endpoint("0.0.0.0:0".parse().unwrap()).unwrap();
        let _ = tokio::time::timeout(
            Duration::from_secs(2),
            transport::connect(&junk_ep, boot.addr, "localhost"),
        )
        .await;
    }

    // The session must still be functionally alive: a second command still round-
    // trips through the server's PTY and back. Pre-fix the server is gone and this
    // never arrives, so `expect_contains` times out and the test fails.
    client.type_str("echo zzPOST\r");
    client.expect_contains("zzPOST").await;

    drop(boot);
}
