//! End-to-end scrollback over a real QUIC connection: a server feeds content
//! that scrolls into history, then a client fetches a window of that history
//! over a reliable side-channel and gets the scrolled-off rows back.

use std::sync::Arc;
use std::time::Duration;

use mish::scrollback::{fetch_history, serve_history};
use mish_quic::transport;
use mish_terminal::emulator::Emulator;
use mish_terminal::history::HistoryRequest;
use tokio::sync::oneshot;

#[tokio::test]
async fn scrollback_fetch_over_quic() {
    let (server_ep, addr, _cert) = transport::loopback_server().unwrap();

    let (ready_tx, ready_rx) = oneshot::channel::<()>();
    let server_task = tokio::spawn(async move {
        let t = Arc::new(transport::accept(&server_ep).await.unwrap());
        // A server emulator with more output than fits on screen, so most of it
        // lands in scrollback history.
        let emu = Emulator::shared(20, 4);
        {
            let mut e = emu.lock().unwrap();
            for i in 0..30 {
                e.feed(format!("row{i}\r\n").as_bytes());
            }
        }
        ready_tx.send(()).ok();
        serve_history(t, emu).await;
    });

    let client_ep = transport::loopback_client().unwrap();
    let t = transport::connect(&client_ep, addr, "localhost")
        .await
        .unwrap();
    ready_rx.await.unwrap();

    // Fetch a window deep in history.
    let resp = tokio::time::timeout(
        Duration::from_secs(10),
        fetch_history(
            &t,
            &HistoryRequest {
                top_above: 20,
                count: 4,
            },
        ),
    )
    .await
    .expect("a timely fetch")
    .expect("a history response");

    assert!(
        resp.history_size >= 20,
        "most of the output scrolled into history (got {})",
        resp.history_size
    );
    assert_eq!(resp.cols, 20);
    assert_eq!(resp.rows.len(), 4, "got the 4 requested rows");
    let text: Vec<String> = resp
        .rows
        .iter()
        .map(|r| {
            r.iter()
                .map(|c| c.c)
                .collect::<String>()
                .trim_end()
                .to_string()
        })
        .collect();
    assert!(
        text.iter().all(|l| l.starts_with("row")),
        "every history row should carry its scrolled-off text, got {text:?}"
    );

    server_task.abort();
}
