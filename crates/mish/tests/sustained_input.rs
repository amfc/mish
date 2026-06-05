//! Regression for sustained client→server input over real QUIC: a burst of
//! keystrokes typed over time must *all* reach the server's PTY, not just the
//! first. `full_stack` only types a single command early, so it can't catch a
//! protocol/driver fault that strands later keystroke states; this does.

use std::sync::Arc;
use std::time::Duration;

use mish::client::{run_client, ClientInput};
use mish::server::{run_server, PtyControl};
use mish_quic::transport;
use mish_ssp::clock::{Clock, SystemClock};
use mish_terminal::emulator::Emulator;
use tokio::sync::mpsc;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sustained_keystrokes_all_arrive() {
    let (server_ep, addr, _cert) = transport::loopback_server().unwrap();
    let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());

    // Server with a *fake* PTY: we never feed output, we just record the input
    // control messages the session forwards. Keep `pty_out_tx` alive so the
    // server doesn't see the child exit.
    let (pty_out_tx, pty_output) = mpsc::channel::<Vec<u8>>(64);
    let (pty_in_tx, mut pty_in_rx) = mpsc::unbounded_channel::<PtyControl>();
    let sclock = clock.clone();
    tokio::spawn(async move {
        let t = transport::accept(&server_ep).await.expect("accept");
        let emu = Emulator::shared(80, 24);
        run_server(Arc::new(t), emu, sclock, None, pty_output, pty_in_tx).await;
    });

    // Collect keystroke bytes the server applied to the PTY.
    let received = Arc::new(tokio::sync::Mutex::new(Vec::<u8>::new()));
    let received2 = received.clone();
    tokio::spawn(async move {
        while let Some(ctl) = pty_in_rx.recv().await {
            if let PtyControl::Input(b) = ctl {
                received2.lock().await.extend_from_slice(&b);
            }
        }
    });

    // Client over real QUIC with a channel-faked TTY.
    let client_ep = transport::loopback_client().unwrap();
    let t = transport::connect(&client_ep, addr, "localhost")
        .await
        .expect("connect");
    let (cin_tx, cin_rx) = mpsc::channel::<ClientInput>(64);
    let (cout_tx, _cout_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    tokio::spawn(run_client(
        Arc::new(t),
        80,
        24,
        clock.clone(),
        mish_terminal::predict::PredictMode::Never,
        None,
        cin_rx,
        cout_tx,
    ));

    // Let the session settle (initial resize handshake), then type a sequence of
    // distinct keystrokes one at a time, with a gap between each — mimicking a
    // human at a prompt, the exact pattern the latency harness exercises.
    tokio::time::sleep(Duration::from_millis(500)).await;
    const SEQ: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    for &c in SEQ {
        cin_tx.send(ClientInput::Keys(vec![c])).await.unwrap();
        tokio::time::sleep(Duration::from_millis(60)).await;
    }

    // Every keystroke must have reached the server's PTY, in order.
    let ok = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if received.lock().await.as_slice() == SEQ {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await;

    let got = received.lock().await.clone();
    assert!(
        ok.is_ok(),
        "not all keystrokes arrived: expected {} bytes {:?}, got {} bytes {:?}",
        SEQ.len(),
        String::from_utf8_lossy(SEQ),
        got.len(),
        String::from_utf8_lossy(&got),
    );

    drop(cin_tx);
    drop(pty_out_tx);
}
