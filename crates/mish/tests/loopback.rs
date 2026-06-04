//! Headless end-to-end test of the full server↔client session loops over the
//! in-memory transport, with the PTY and TTY faked by channels. Proves the two
//! halves wire together: server output reaches the client's screen, and client
//! keystrokes/resizes reach the server's PTY.

use std::sync::Arc;
use std::time::Duration;

use mish::client::{run_client, ClientInput};
use mish::server::{run_server, PtyControl};
use mish_ssp::clock::{Clock, SystemClock, TokioClock};
use mish_ssp::memory;
use tokio::sync::mpsc;

/// Port of mosh's server-network-timeout.test: with no client ever sending,
/// the server shuts itself down after MOSH_SERVER_NETWORK_TMOUT. Uses paused
/// virtual time so the 10s timeout elapses instantly.
#[tokio::test(start_paused = true)]
async fn server_exits_after_network_timeout() {
    // A connected-but-silent transport (no client Driver on the other end).
    let (server_t, _client_t) = memory::pair();
    let clock: Arc<dyn Clock> = Arc::new(TokioClock::new());
    let (_pty_out_tx, pty_out_rx) = mpsc::channel::<Vec<u8>>(64);
    let (pty_in_tx, _pty_in_rx) = mpsc::unbounded_channel::<PtyControl>();

    let server = tokio::spawn(run_server(
        Arc::new(server_t),
        80,
        24,
        clock,
        Some(Duration::from_secs(10)),
        pty_out_rx,
        pty_in_tx,
    ));

    // Step virtual time forward (yielding so the server/driver tasks register
    // and fire their timers) until the server exits or we pass the deadline.
    for _ in 0..30 {
        if server.is_finished() {
            break;
        }
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
    }
    assert!(server.is_finished(), "server should exit after the network timeout");
    server.await.expect("server task joined");
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

#[tokio::test]
async fn server_output_reaches_client_and_input_reaches_server() {
    let (ta, tb) = memory::pair();
    let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());

    // Server with a fake PTY.
    let (pty_out_tx, pty_out_rx) = mpsc::channel::<Vec<u8>>(64);
    let (pty_in_tx, mut pty_in_rx) = mpsc::unbounded_channel::<PtyControl>();
    tokio::spawn(run_server(
        Arc::new(ta),
        80,
        24,
        clock.clone(),
        None,
        pty_out_rx,
        pty_in_tx,
    ));

    // Client with a fake TTY.
    let (cin_tx, cin_rx) = mpsc::channel::<ClientInput>(64);
    let (cout_tx, mut cout_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    tokio::spawn(run_client(
        Arc::new(tb),
        80,
        24,
        clock.clone(),
        mish_terminal::predict::PredictMode::Never,
        cin_rx,
        cout_tx,
    ));

    // 1. Child writes output → client renders a frame containing it.
    pty_out_tx.send(b"hello world".to_vec()).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let frame = cout_rx.recv().await.expect("client output");
            if contains(&frame, b"hello world") {
                return;
            }
        }
    })
    .await
    .expect("client should render server output");

    // 2. User types → server's PTY receives the keystrokes.
    cin_tx
        .send(ClientInput::Keys(b"ls -la\r".to_vec()))
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match pty_in_rx.recv().await.expect("pty control") {
                PtyControl::Input(b) if b == b"ls -la\r" => return,
                _ => {} // skip the client's initial resize, etc.
            }
        }
    })
    .await
    .expect("server should receive client keystrokes");
}

#[tokio::test]
async fn client_resize_propagates_to_server_pty() {
    let (ta, tb) = memory::pair();
    let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());

    let (_pty_out_tx, pty_out_rx) = mpsc::channel::<Vec<u8>>(64);
    let (pty_in_tx, mut pty_in_rx) = mpsc::unbounded_channel::<PtyControl>();
    tokio::spawn(run_server(
        Arc::new(ta),
        80,
        24,
        clock.clone(),
        None,
        pty_out_rx,
        pty_in_tx,
    ));

    let (cin_tx, cin_rx) = mpsc::channel::<ClientInput>(64);
    let (cout_tx, _cout_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    tokio::spawn(run_client(
        Arc::new(tb),
        80,
        24,
        clock.clone(),
        mish_terminal::predict::PredictMode::Never,
        cin_rx,
        cout_tx,
    ));

    cin_tx
        .send(ClientInput::Resize { cols: 132, rows: 43 })
        .await
        .unwrap();

    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let PtyControl::Resize { cols, rows } = pty_in_rx.recv().await.expect("pty control") {
                if cols == 132 && rows == 43 {
                    return;
                }
            }
        }
    })
    .await
    .expect("server PTY should be resized");
}
