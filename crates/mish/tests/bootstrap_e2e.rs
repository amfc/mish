//! End-to-end test of the mosh-style bootstrap: spawn the real `mish-server`
//! binary (as `--local` mode does), parse its `MISH CONNECT <port> <cert>` line,
//! open the QUIC session to that UDP port trusting the printed certificate, and
//! drive a real shell through it.

use std::sync::Arc;
use std::time::Duration;

use mish::bootstrap;
use mish::client::{run_client, ClientInput};
use mish_quic::transport;
use mish_ssp::clock::{Clock, SystemClock};
use mish_terminal::predict::PredictMode;
use tokio::sync::mpsc;

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_bootstrap_starts_server_and_connects() {
    // Cargo provides the built binary's path to integration tests.
    let server = env!("CARGO_BIN_EXE_mish-server");

    // Start the server child, read MISH CONNECT, learn (addr, cert).
    let boot = bootstrap::local(server, false, false, None, &["/bin/sh".to_string()])
        .await
        .expect("bootstrap should start the server and parse MISH CONNECT");
    assert_ne!(boot.addr.port(), 0, "got a real UDP port");
    assert!(!boot.server_cert_der.is_empty(), "got a server certificate");
    assert!(!boot.client_key_der.is_empty(), "got client credentials");

    // Connect over QUIC with mutual auth using the bootstrapped credentials.
    let endpoint = transport::authenticated_client_endpoint(
        "0.0.0.0:0".parse().unwrap(),
        &boot.server_cert_der,
        &boot.client_cert_der,
        &boot.client_key_der,
    )
    .expect("client endpoint");
    let t = transport::connect(&endpoint, boot.addr, "localhost")
        .await
        .expect("connect to bootstrapped server");

    // Drive a channel-faked terminal session through the real server's PTY.
    let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
    let (cin_tx, cin_rx) = mpsc::channel::<ClientInput>(64);
    let (cout_tx, mut cout_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    tokio::spawn(run_client(
        Arc::new(t),
        80,
        24,
        clock,
        PredictMode::Never,
        None,
        None, // session name (display-only)
        cin_rx,
        cout_tx,
    ));

    cin_tx
        .send(ClientInput::Keys(b"echo BOOTSTRAP_OK\r".to_vec()))
        .await
        .unwrap();

    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let frame = cout_rx.recv().await.expect("client output");
            if contains(&frame, b"BOOTSTRAP_OK") {
                return;
            }
        }
    })
    .await
    .expect("command output should traverse the bootstrapped session");

    drop(boot); // tears down the server child
}

/// Regression for the `-- command with arguments` bug: a multi-word command
/// must reach the server's PTY as real argv, not a single joined `argv[0]`.
/// Before the fix the client/server `join(" ")`d the trailing args and the
/// server tried to exec a program literally named "/bin/sh -c echo …", which
/// `portable-pty` could not spawn — the server exited and the client hung on a
/// blank screen. `sh -c '<string>'` is also exactly how a wrapper (e.g. clauc)
/// runs an arbitrary shell command over mish, so this covers that path too. The
/// `sleep` keeps the session alive long enough for the marker to resync to us.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_bootstrap_runs_multiword_command() {
    let server = env!("CARGO_BIN_EXE_mish-server");

    let command = [
        "/bin/sh".to_string(),
        "-c".to_string(),
        "echo MULTI_WORD_OK; sleep 10".to_string(),
    ];
    let boot = bootstrap::local(server, false, false, None, &command)
        .await
        .expect("bootstrap should start the server and parse MISH CONNECT");

    let endpoint = transport::authenticated_client_endpoint(
        "0.0.0.0:0".parse().unwrap(),
        &boot.server_cert_der,
        &boot.client_cert_der,
        &boot.client_key_der,
    )
    .expect("client endpoint");
    let t = transport::connect(&endpoint, boot.addr, "localhost")
        .await
        .expect("connect to bootstrapped server");

    let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
    let (_cin_tx, cin_rx) = mpsc::channel::<ClientInput>(64);
    let (cout_tx, mut cout_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    tokio::spawn(run_client(
        Arc::new(t),
        80,
        24,
        clock,
        PredictMode::Never,
        None,
        None,
        cin_rx,
        cout_tx,
    ));

    // The command runs on connect and exits; its output is resynced to us. If
    // the argv had been joined, the PTY spawn would have failed and this marker
    // would never arrive (the old symptom: a hang until the timeout).
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            match cout_rx.recv().await {
                Some(frame) if contains(&frame, b"MULTI_WORD_OK") => return true,
                Some(_) => continue,
                None => return false, // session closed with no marker
            }
        }
    })
    .await
    .expect("multi-word command output should arrive before the timeout")
    .then_some(())
    .expect("server must exec the multi-word command as real argv");

    drop(boot);
}
