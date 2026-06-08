//! Regression: a long run of output (250 lines) plus the command that produced
//! it must *all* be reachable — the lines still on the live screen, every line
//! that scrolled into history, and the command line at the very top.
//!
//! Drives the real client/server loops over real QUIC with the reliable history
//! side-channel, exactly as the binary does, then walks scrollback to the top and
//! asserts full coverage.

use std::sync::Arc;
use std::time::Duration;

use mish::client::{run_client, ClientInput, HistoryFetcher};
use mish::server::run_server;
use mish_quic::transport;
use mish_ssp::clock::{Clock, SystemClock};
use mish_terminal::emulator::Emulator;
use mish_terminal::history::{HistoryRequest, HistoryResponse};
use tokio::sync::mpsc;

const COLS: u16 = 80;
const ROWS: u16 = 24;
const N: u32 = 250;

struct QuicHistory(Arc<transport::QuicTransport>);
#[async_trait::async_trait]
impl HistoryFetcher for QuicHistory {
    async fn fetch(&self, top_above: u32, count: u16) -> Option<HistoryResponse> {
        mish::scrollback::fetch_history(&self.0, &HistoryRequest { top_above, count }).await
    }
}

/// The `MARK<n> END` numbers in a blob of rendered terminal bytes.
fn marks(bytes: &[u8]) -> Vec<u32> {
    let s = String::from_utf8_lossy(bytes);
    let mut out = Vec::new();
    for seg in s.split("MARK").skip(1) {
        let num: String = seg.chars().take_while(|c| c.is_ascii_digit()).collect();
        if !num.is_empty() && seg[num.len()..].starts_with(" END") {
            if let Ok(n) = num.parse() {
                out.push(n);
            }
        }
    }
    out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deep_scrollback_reaches_every_line_and_the_command() {
    let (server_ep, addr, _c) = transport::loopback_server().unwrap();
    let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
    let emu = Emulator::shared(COLS, ROWS);

    let (pty_out_tx, pty_output) = mpsc::channel::<Vec<u8>>(256);
    let (pty_in_tx, mut pty_in_rx) = mpsc::unbounded_channel();
    tokio::spawn(async move { while pty_in_rx.recv().await.is_some() {} });

    let sclock = clock.clone();
    let semu = emu.clone();
    tokio::spawn(async move {
        let t = Arc::new(transport::accept(&server_ep).await.unwrap());
        tokio::spawn(mish::scrollback::serve_history(t.clone(), semu.clone()));
        run_server(t, semu, sclock, None, pty_output, pty_in_tx).await;
    });

    let client_ep = transport::loopback_client().unwrap();
    let t = Arc::new(transport::connect(&client_ep, addr, "localhost").await.unwrap());
    let (cin_tx, cin_rx) = mpsc::channel::<ClientInput>(64);
    let (cout_tx, mut cout_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let hist: Arc<dyn HistoryFetcher> = Arc::new(QuicHistory(t.clone()));
    tokio::spawn(run_client(
        t.clone(),
        COLS,
        ROWS,
        clock.clone(),
        mish_terminal::predict::PredictMode::Never,
        Some(hist),
        None, // session name (display-only)
        cin_rx,
        cout_tx,
    ));

    // Collect everything rendered during `dur` into one blob.
    async fn drain(rx: &mut mpsc::UnboundedReceiver<Vec<u8>>, dur: Duration) -> Vec<u8> {
        let mut buf = Vec::new();
        let _ = tokio::time::timeout(dur, async {
            while let Some(f) = rx.recv().await {
                buf.extend_from_slice(&f);
            }
        })
        .await;
        buf
    }

    // The command, then its 250 lines of output.
    tokio::time::sleep(Duration::from_millis(400)).await;
    pty_out_tx
        .send(b"$ for i in $(seq 1 250); do echo MARK$i END; done CMD_SENTINEL\r\n".to_vec())
        .await
        .unwrap();
    for i in 1..=N {
        pty_out_tx.send(format!("MARK{i} END\r\n").into_bytes()).await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(600)).await;

    // Everything ever shown to the user: start with the live screen (the newest
    // lines, which never enter scrollback), then walk scrollback to the top.
    let mut seen = std::collections::BTreeSet::new();
    let mut saw_command = false;
    // Discard the streaming frames, then force a full repaint so we capture the
    // *current* live screen in one frame (its newest rows never reach scrollback).
    let _ = drain(&mut cout_rx, Duration::from_millis(200)).await;
    cin_tx.send(ClientInput::Redraw).await.unwrap();
    let live = drain(&mut cout_rx, Duration::from_millis(200)).await;
    seen.extend(marks(&live));

    // Page up well past the top (ROWS * 20 > N + command); contiguous anchoring
    // means each page covers a fresh ROWS-row slice with no gaps.
    for _ in 0..20 {
        cin_tx.send(ClientInput::ScrollUp).await.unwrap();
        let frame = drain(&mut cout_rx, Duration::from_millis(120)).await;
        seen.extend(marks(&frame));
        if String::from_utf8_lossy(&frame).contains("CMD_SENTINEL") {
            saw_command = true;
        }
    }

    let missing: Vec<u32> = (1..=N).filter(|n| !seen.contains(n)).collect();
    assert!(
        missing.is_empty(),
        "every one of the {N} lines must be reachable (live screen + scrollback); \
         missing {} of them: {:?}{}",
        missing.len(),
        &missing[..missing.len().min(20)],
        if missing.len() > 20 { " …" } else { "" }
    );
    assert!(
        saw_command,
        "scrolling to the top must reveal the command that produced the output"
    );

    drop(cin_tx);
    drop(pty_out_tx);
}
