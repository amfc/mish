//! Regression: scrollback must stay anchored to the buffer, not the live edge.
//!
//! When output arrives while the user is scrolled up, the server's history grows
//! at the *bottom*. A scroll position measured as "lines above the live top row"
//! then slides out from under the user — the same offset points at ever-older
//! content, and the rows just above the live screen become unreachable. (Reported
//! as scrollback "overwriting" earlier output and getting stuck after a noisy
//! prompt.) The client anchors the viewport to a fixed point in the buffer
//! instead, so a page-up always advances exactly one page through the content
//! regardless of concurrent output.
//!
//! This drives the real client/server loops over real QUIC with the reliable
//! history side-channel, feeding distinctly-numbered lines so we can tell which
//! window each scroll lands on.

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

/// History fetcher backed by the live QUIC side-channel (same path the binary
/// uses), so the server answers from its actual, growing scrollback.
struct QuicHistory(Arc<transport::QuicTransport>);
#[async_trait::async_trait]
impl HistoryFetcher for QuicHistory {
    async fn fetch(&self, top_above: u32, count: u16) -> Option<HistoryResponse> {
        mish::scrollback::fetch_history(&self.0, &HistoryRequest { top_above, count }).await
    }
}

/// The `MARK<n> END` line numbers present in a blob of rendered terminal bytes.
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
    out.sort_unstable();
    out.dedup();
    out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scroll_window_stays_anchored_when_output_arrives() {
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

    // Capture the marks the client renders during the next `dur`.
    async fn window(rx: &mut mpsc::UnboundedReceiver<Vec<u8>>, dur: Duration) -> Vec<u32> {
        let mut buf = Vec::new();
        let _ = tokio::time::timeout(dur, async {
            while let Some(f) = rx.recv().await {
                buf.extend_from_slice(&f);
            }
        })
        .await;
        marks(&buf)
    }

    // Build 200 lines of history.
    tokio::time::sleep(Duration::from_millis(400)).await;
    for i in 1..=200u32 {
        pty_out_tx.send(format!("MARK{i} END\r\n").into_bytes()).await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    while cout_rx.try_recv().is_ok() {} // discard the live frames

    // Scroll up two pages; the second page is our reference window W1.
    cin_tx.send(ClientInput::ScrollUp).await.unwrap();
    let _ = window(&mut cout_rx, Duration::from_millis(250)).await;
    cin_tx.send(ClientInput::ScrollUp).await.unwrap();
    let w1 = window(&mut cout_rx, Duration::from_millis(250)).await;
    assert!(!w1.is_empty(), "scroll-up should render a history window");

    // Output arrives while we sit scrolled: 60 new lines grow the buffer at the
    // bottom (more than two pages above us would be if anchored to the live edge).
    for k in 1..=60u32 {
        pty_out_tx.send(format!("FILL{k}\r\n").into_bytes()).await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    while cout_rx.try_recv().is_ok() {}

    // One more page up must show *older* content, contiguous with W1 — not a
    // window shifted by the 60 new lines. With the old live-edge anchor, W2 would
    // overlap or sit *newer* than W1 (scrolling up appeared to go nowhere / back).
    cin_tx.send(ClientInput::ScrollUp).await.unwrap();
    let w2 = window(&mut cout_rx, Duration::from_millis(300)).await;
    assert!(!w2.is_empty(), "scroll-up after output should still render history");

    let w1_min = *w1.iter().min().unwrap();
    let w2_max = *w2.iter().max().unwrap();
    assert!(
        w2_max < w1_min,
        "scroll-up after concurrent output must advance to older content: \
         W1 marks {w1:?} (min {w1_min}), W2 marks {w2:?} (max {w2_max}) — \
         W2 should be strictly older than W1, not shifted by the new output"
    );
    // And contiguous: W2's newest line should be adjacent to W1's oldest (one page
    // of ROWS rows between them, give or take the cursor row), not a big gap.
    assert!(
        w1_min - w2_max <= 3,
        "scroll-up should advance one contiguous page, leaving no gap: \
         W1 min {w1_min}, W2 max {w2_max}"
    );

    drop(cin_tx);
    drop(pty_out_tx);
}
