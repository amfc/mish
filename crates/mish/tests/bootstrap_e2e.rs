//! End-to-end test of the mosh-style bootstrap: spawn the real `mish-server`
//! binary (as `--local` mode does), parse its `MISH CONNECT <port> <cert>` line,
//! open the QUIC session to that UDP port trusting the printed certificate, and
//! drive a real shell through it.

use std::sync::Arc;
use std::time::Duration;

use mish::bootstrap;
use mish::client::{run_client, ClientInput};
use mish_quic::{transport, CertificateDer};
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
    let boot = bootstrap::local(server, Some("/bin/sh"))
        .await
        .expect("bootstrap should start the server and parse MISH CONNECT");
    assert_ne!(boot.addr.port(), 0, "got a real UDP port");
    assert!(!boot.cert_der.is_empty(), "got a certificate");

    // Connect over QUIC, trusting exactly the bootstrapped certificate.
    let cert = CertificateDer::from(boot.cert_der.clone());
    let endpoint =
        transport::client_endpoint("0.0.0.0:0".parse().unwrap(), cert).expect("client endpoint");
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
