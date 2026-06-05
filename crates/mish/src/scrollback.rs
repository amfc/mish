//! Server side of scrollback: answer client history requests over reliable QUIC
//! side-channels, reading from the shared emulator's scrollback.
//!
//! Runs alongside [`crate::server::run_server`]: the session loop feeds the live
//! screen over datagrams as usual, while this task accepts side-channel streams
//! and serves [`HistoryRequest`]s from the *same* emulator (shared via
//! `Arc<Mutex<…>>`). History never touches the per-frame diff — it's fetched on
//! demand, reliably, only when the user scrolls up.

use std::sync::{Arc, Mutex};

use mish_quic::transport::QuicTransport;
use mish_quic::{RecvStream, SendStream};
use mish_ssp::framing::{read_message, write_message, MAX_MESSAGE_LEN};
use mish_terminal::emulator::Emulator;
use mish_terminal::history::{answer_history, HistoryRequest};

/// Accept side-channel streams on `transport` and answer each as a one-shot
/// history request/response, until the connection goes away. Each request is
/// served on its own task so a slow client can't block others.
pub async fn serve_history(transport: Arc<QuicTransport>, emu: Arc<Mutex<Emulator>>) {
    loop {
        let (send, recv) = match transport.accept_side_channel().await {
            Ok(s) => s,
            Err(_) => return, // connection closed / gone
        };
        let emu = emu.clone();
        tokio::spawn(async move {
            serve_one(send, recv, emu).await;
        });
    }
}

/// Serve a single side-channel: read one [`HistoryRequest`], answer it, finish.
async fn serve_one(mut send: SendStream, mut recv: RecvStream, emu: Arc<Mutex<Emulator>>) {
    let bytes = match read_message(&mut recv, MAX_MESSAGE_LEN).await {
        Ok(Some(b)) => b,
        _ => return, // empty or malformed framing
    };
    let Some(req) = HistoryRequest::decode(&bytes) else {
        return; // not a valid request
    };
    // Brief lock to snapshot the requested history window.
    let resp = {
        let e = emu.lock().unwrap();
        answer_history(&e, &req)
    };
    if write_message(&mut send, &resp.encode()).await.is_ok() {
        let _ = send.finish();
    }
}

/// Client side: fetch a window of history rows over a fresh side-channel.
/// Returns the server's [`HistoryResponse`](mish_terminal::history::HistoryResponse).
pub async fn fetch_history(
    transport: &QuicTransport,
    req: &HistoryRequest,
) -> Option<mish_terminal::history::HistoryResponse> {
    let (mut send, mut recv) = transport.open_side_channel().await.ok()?;
    write_message(&mut send, &req.encode()).await.ok()?;
    send.finish().ok()?;
    let bytes = read_message(&mut recv, MAX_MESSAGE_LEN).await.ok()??;
    mish_terminal::history::HistoryResponse::decode(&bytes)
}
