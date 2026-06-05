//! The whole production stack in one test: a real `/bin/sh` on a real PTY,
//! served over a real QUIC connection, driven by the real client session loop.
//! Only the client's TTY is faked (channels instead of raw stdin/stdout), since
//! a test harness has no controlling terminal.
//!
//! This is the integration that proves QUIC + SSP + emulator + PTY + render all
//! fit together end to end.

use std::sync::Arc;
use std::time::Duration;

use mish::client::{run_client, ClientInput};
use mish::pty::PtyProcess;
use mish::server::run_server;
use mish_quic::transport;
use mish_ssp::clock::{Clock, SystemClock};
use tokio::sync::mpsc;

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quic_pty_full_stack() {
    let (server_ep, addr, _cert) = transport::loopback_server().unwrap();
    let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());

    // Server: accept a QUIC connection, spawn a real shell, run the session.
    let sclock = clock.clone();
    tokio::spawn(async move {
        let t = transport::accept(&server_ep).await.expect("accept");
        let pty = PtyProcess::spawn("/bin/sh", 80, 24).expect("spawn shell");
        let emu = mish_terminal::emulator::Emulator::shared(80, 24);
        run_server(Arc::new(t), emu, sclock, None, pty.output, pty.control).await;
    });

    // Client: connect over QUIC, run the session with a channel-faked TTY.
    let client_ep = transport::loopback_client().unwrap();
    let t = transport::connect(&client_ep, addr, "localhost")
        .await
        .expect("connect");
    let (cin_tx, cin_rx) = mpsc::channel::<ClientInput>(64);
    let (cout_tx, mut cout_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    tokio::spawn(run_client(
        Arc::new(t),
        80,
        24,
        clock.clone(),
        mish_terminal::predict::PredictMode::Never,
        cin_rx,
        cout_tx,
    ));

    // Type a command and watch it come back rendered.
    cin_tx
        .send(ClientInput::Keys(b"echo FULLSTACK_OK\r".to_vec()))
        .await
        .unwrap();

    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let frame = cout_rx.recv().await.expect("client output");
            if contains(&frame, b"FULLSTACK_OK") {
                return;
            }
        }
    })
    .await
    .expect("command output should traverse QUIC+PTY and render on the client");
}
