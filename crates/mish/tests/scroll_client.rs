//! Headless test of the client's scrollback mode: a `ScrollUp` makes `run_client`
//! fetch history (through the injected [`HistoryFetcher`]) and render that window
//! to the TTY; `ScrollDown` past the bottom returns to the live screen. Uses the
//! in-memory transport and a fake fetcher, so it needs no QUIC or server.

use std::sync::Arc;
use std::time::Duration;

use mish::client::{run_client, ClientInput, HistoryFetcher};
use mish_ssp::clock::{Clock, SystemClock};
use mish_ssp::memory;
use mish_terminal::history::HistoryResponse;
use mish_terminal::predict::PredictMode;
use mish_terminal::screen::Cell;
use tokio::sync::mpsc;
use tokio::time::timeout;

const COLS: u16 = 20;
const ROWS: u16 = 5;

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// A fetcher that synthesizes recognizable history rows ("HIST<n>") so we can
/// assert the rendered frame came from history.
struct FakeHistory;

#[async_trait::async_trait]
impl HistoryFetcher for FakeHistory {
    async fn fetch(&self, top_above: u32, count: u16) -> Option<HistoryResponse> {
        let rows = (0..count)
            .map(|r| {
                let text = format!("HIST{}", top_above as u16 + r);
                let mut row: Vec<Cell> = text
                    .chars()
                    .map(|c| Cell {
                        c,
                        ..Cell::default()
                    })
                    .collect();
                row.resize(COLS as usize, Cell::default());
                row
            })
            .collect();
        Some(HistoryResponse {
            history_size: 100,
            cols: COLS,
            rows,
        })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scroll_up_renders_history() {
    let (ca, _cb) = memory::pair();
    let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
    let (in_tx, in_rx) = mpsc::channel::<ClientInput>(64);
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let history: Arc<dyn HistoryFetcher> = Arc::new(FakeHistory);

    tokio::spawn(run_client(
        Arc::new(ca),
        COLS,
        ROWS,
        clock,
        PredictMode::Never,
        Some(history),
        in_rx,
        out_tx,
    ));

    // Enter scrollback: the client should fetch and paint the history window.
    in_tx.send(ClientInput::ScrollUp).await.unwrap();

    timeout(Duration::from_secs(5), async {
        loop {
            let frame = out_rx.recv().await.expect("a rendered frame");
            if contains(&frame, b"HIST") {
                return;
            }
        }
    })
    .await
    .expect("scroll-up should render history rows to the TTY");
}
