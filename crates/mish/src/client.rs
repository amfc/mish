//! The client session loop: bridges the user's terminal to the SSP layer.
//!
//! The client synchronizes `UserStream` (out) and receives `Screen` (in): it is
//! an `SspCore<UserStream, Screen>`. Like the server, it is generic over the
//! transport and decoupled from the real TTY via channels — input events come in
//! on one channel, rendered output goes out on another — so it can be tested
//! headlessly. The binary wires raw stdin/stdout and SIGWINCH into these.

use std::sync::Arc;

use mish_ssp::clock::Clock;
use mish_ssp::core::SspConfig;
use mish_ssp::session::{Driver, Session};
use mish_ssp::state::SyncState;
use mish_ssp::transport::Transport;
use mish_terminal::display::new_frame;
use mish_terminal::history::HistoryResponse;
use mish_terminal::predict::{PredictMode, PredictionEngine};
use mish_terminal::screen::Screen;
use mish_terminal::user::UserStream;
use tokio::sync::mpsc;

/// An input event from the user's terminal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientInput {
    /// Raw keystroke bytes to forward to the remote shell.
    Keys(Vec<u8>),
    /// The local terminal was resized.
    Resize { cols: u16, rows: u16 },
    /// Force a full repaint of the current screen (e.g. after resuming from
    /// suspend, where the real terminal's contents were lost / changed).
    Redraw,
    /// Scroll one page up into the server-held scrollback history.
    ScrollUp,
    /// Scroll one page back down toward the live screen (exits scrollback at 0).
    ScrollDown,
    /// The user detached (e.g. Ctrl-]): begin a clean shutdown.
    Detach,
}

/// Fetches server-held scrollback history for the client's scroll mode. The
/// session loop is transport-generic, so history retrieval (which needs a
/// reliable side-channel — see [`crate::scrollback`]) is injected through this
/// trait. Headless tests supply a fake; the binary supplies a QUIC-backed one.
#[async_trait::async_trait]
pub trait HistoryFetcher: Send + Sync {
    /// Fetch `count` rows of history starting `top_above` lines above the live
    /// top row. `None` if the fetch failed (the client simply stays put).
    async fn fetch(&self, top_above: u32, count: u16) -> Option<HistoryResponse>;
}

/// Compose a [`Screen`] to display for a scrollback window: the fetched rows
/// laid out at the client's geometry, cursor hidden, with a title hint.
fn history_screen(resp: &HistoryResponse, cols: u16, rows: u16, offset: u32) -> Screen {
    let mut s = Screen::blank(cols, rows);
    for (r, row) in resp.rows.iter().take(rows as usize).enumerate() {
        let base = r * cols as usize;
        for (c, cell) in row.iter().take(cols as usize).enumerate() {
            s.cells[base + c] = cell.clone();
        }
    }
    s.cursor_visible = false;
    s.title = format!("scrollback ↑{offset} (Shift-PgDn to return)");
    s
}

/// Run a client session until input ends or the peer leaves.
///
/// * `input` yields [`ClientInput`] from the user's terminal.
/// * `output` receives the bytes to write to the user's terminal (a full-frame
///   ANSI repaint per remote screen update).
#[allow(clippy::too_many_arguments)] // session entry point: discrete wired-in pieces
pub async fn run_client<T: Transport>(
    transport: Arc<T>,
    cols: u16,
    rows: u16,
    clock: Arc<dyn Clock>,
    predict: PredictMode,
    history: Option<Arc<dyn HistoryFetcher>>,
    mut input: mpsc::Receiver<ClientInput>,
    output: mpsc::UnboundedSender<Vec<u8>>,
) {
    let (driver, handle) =
        Driver::<T, UserStream, Screen>::with(transport, clock.clone(), SspConfig::default());
    let driver_task = driver.spawn();

    // Accumulate the user-input log. We keep the full prefix so diffs against
    // older acknowledged states stay valid; the SSP layer trims acked events
    // from the copies it actually sends.
    let mut stream = UserStream::new();
    // Tell the server our initial geometry up front.
    stream.push_resize(cols, rows);
    handle.set_local(stream.clone());

    let mut remote = handle.subscribe_remote();
    let mut engine = PredictionEngine::new(predict);
    // Latest screen actually received from the server (predictions overlay it).
    let mut server_screen = Screen::new_initial();
    // Last screen we painted to the TTY; new frames diff against it so we emit
    // only minimal updates (mosh's Display::new_frame), not full repaints.
    let mut painted = Screen::new_initial();
    let mut painted_once = false;

    // Scrollback state: when `scroll_offset > 0` the client is paused in history,
    // showing `scroll_view` (the last fetched window) instead of the live screen;
    // live updates still arrive but don't disturb the view.
    let mut scroll_offset: u32 = 0;
    let mut scroll_view: Option<Screen> = None;

    // Emit a minimal frame from `painted` to the screen to show: either the
    // scrollback window (when scrolled) or the predicted live screen with a
    // connection-status banner overlaid when the link has gone silent.
    macro_rules! repaint {
        () => {{
            let now = clock.now_ms();
            let mut shown = if let Some(view) = &scroll_view {
                view.clone()
            } else {
                // Keep adaptive prediction in step with the measured link latency
                // and let long-pending predictions escalate the glitch trigger.
                engine.set_srtt(handle.srtt_ms());
                engine.advance(now);
                let predicted = engine.predicted_screen(&server_screen);
                let silent_secs = now.saturating_sub(handle.last_recv_ms()) / 1000;
                mish_terminal::notification::stalled_overlay(&predicted, silent_secs)
                    .unwrap_or(predicted)
            };
            // Prefix the window title so the user can tell they're in mosh (like
            // upstream's "[mosh] " prefix). Applied only to the painted frame, not
            // the synchronized state, so transparency comparisons are unaffected.
            if !shown.title.starts_with("[mish] ") {
                shown.title = format!("[mish] {}", shown.title);
            }
            let frame = new_frame(&painted, &shown, painted_once);
            painted = shown;
            painted_once = true;
            if !frame.is_empty() && output.send(frame).is_err() {
                break;
            }
        }};
    }

    // Wake periodically so the stall banner appears (and its "N seconds" counts
    // up) even when no input or screen update is flowing.
    let mut tick = tokio::time::interval(std::time::Duration::from_millis(500));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = tick.tick() => { repaint!(); }
            inp = input.recv() => {
                // Leaving scrollback: drop the history view and force a full
                // repaint of the live screen on the next `repaint!`.
                macro_rules! exit_scroll {
                    () => {{
                        if scroll_offset != 0 || scroll_view.is_some() {
                            scroll_offset = 0;
                            scroll_view = None;
                            painted_once = false;
                        }
                    }};
                }
                match inp {
                    Some(ClientInput::Keys(b)) => {
                        // Any keystroke returns to the live screen and is forwarded.
                        exit_scroll!();
                        stream.push_keystroke(b.clone());
                        handle.set_local(stream.clone());
                        // Speculatively echo the keystroke immediately.
                        engine.new_user_bytes(&b, &server_screen, stream.total(), clock.now_ms());
                        repaint!();
                    }
                    Some(ClientInput::Resize { cols, rows }) => {
                        exit_scroll!();
                        stream.push_resize(cols, rows);
                        handle.set_local(stream.clone());
                    }
                    // Scroll one page up into server-held history. Fetched over the
                    // reliable side-channel; clamped to the available history.
                    Some(ClientInput::ScrollUp) => {
                        if let Some(h) = &history {
                            let page = rows.max(1) as u32;
                            let target = scroll_offset.saturating_add(page);
                            if let Some(resp) = h.fetch(target, rows).await {
                                let off = target.min(resp.history_size);
                                if off > 0 {
                                    // If the clamp landed on a different offset,
                                    // refetch so the window matches it exactly.
                                    let resp = if off != target {
                                        h.fetch(off, rows).await.unwrap_or(resp)
                                    } else {
                                        resp
                                    };
                                    scroll_offset = off;
                                    scroll_view = Some(history_screen(&resp, cols, rows, off));
                                    painted_once = false;
                                    repaint!();
                                }
                            }
                        }
                    }
                    // Scroll one page back toward the live screen; at the bottom,
                    // leave scrollback entirely.
                    Some(ClientInput::ScrollDown) => {
                        if scroll_offset > 0 {
                            let page = rows.max(1) as u32;
                            let target = scroll_offset.saturating_sub(page);
                            if target == 0 {
                                exit_scroll!();
                                repaint!();
                            } else if let Some(h) = &history {
                                if let Some(resp) = h.fetch(target, rows).await {
                                    scroll_offset = target;
                                    scroll_view = Some(history_screen(&resp, cols, rows, target));
                                    painted_once = false;
                                    repaint!();
                                }
                            }
                        }
                    }
                    // Force a full repaint from scratch (resume-from-suspend): the
                    // real terminal lost our painted state, so re-emit the whole
                    // screen rather than an incremental diff against `painted`.
                    Some(ClientInput::Redraw) => {
                        painted_once = false;
                        repaint!();
                    }
                    // Detach or input closed → begin a clean shutdown.
                    Some(ClientInput::Detach) | None => {
                        tracing::info!(target: "mish::client", "client: detach or input closed; ending session");
                        break;
                    }
                }
            }
            changed = remote.changed() => {
                if changed.is_err() {
                    // The driver task ended — typically because the server began a
                    // clean shutdown (its child exited) and our driver mirrored it.
                    tracing::info!(target: "mish::client", "client: remote driver stopped; ending session");
                    break; // driver stopped
                }
                server_screen = remote.borrow_and_update().clone();
                // Validate/cull predictions against the freshly-confirmed screen.
                engine.new_server_screen(&server_screen, clock.now_ms());
                repaint!();
            }
        }
    }

    // Clean shutdown: ask the peer to close, then wait briefly for the driver to
    // finish the handshake.
    tracing::info!(target: "mish::client", "client: session loop ended; finalizing shutdown handshake");
    handle.shutdown();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), driver_task).await;
    tracing::info!(target: "mish::client", "client: shutdown complete");
}
