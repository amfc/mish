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
use mish_terminal::screen::{Screen, MOUSE_CLICK, MOUSE_SGR};
use mish_terminal::statusbar::LinkStats;
use mish_terminal::user::UserStream;
use tokio::sync::mpsc;

/// Lines fed to an alt-screen pager per mouse-wheel notch (matches the usual
/// terminal alternate-scroll step).
const WHEEL_STEP_LINES: usize = 3;

/// Window (ms) over which the status bar reports packet loss: the delta of the
/// transport's cumulative (sent, lost) counters across this span. One minute,
/// matching the prediction-accuracy window, so both meters cover "the last
/// minute" as the user expects.
const LOSS_WINDOW_MS: u64 = 60_000;

/// Loss fraction (`0.0..=1.0`) across the sampling window: `(lost_now -
/// lost_oldest) / (sent_now - sent_oldest)`. `None` until there are two samples
/// spanning some sent packets (nothing meaningful to divide yet).
fn window_loss(window: &[(u64, u64, u64)]) -> Option<f64> {
    let (_, first_sent, first_lost) = *window.first()?;
    let (_, last_sent, last_lost) = *window.last()?;
    let sent = last_sent.saturating_sub(first_sent);
    let lost = last_lost.saturating_sub(first_lost);
    (sent > 0).then(|| (lost as f64 / sent as f64).clamp(0.0, 1.0))
}

/// Decode an SGR mouse report (`ESC [ < Cb ; Cx ; Cy M`) as a vertical wheel
/// event: `Some(true)` = wheel up, `Some(false)` = wheel down, `None` for any
/// other mouse event. Wheel notches are press-only (`M`).
fn sgr_wheel(seq: &[u8]) -> Option<bool> {
    let body = seq.strip_prefix(b"\x1b[<")?;
    let body = body.strip_suffix(b"M")?; // wheel is a press, never a release
    let cb: u32 = std::str::from_utf8(body)
        .ok()?
        .split(';')
        .next()?
        .parse()
        .ok()?;
    // Wheel group: bit 6 set, bit 7 clear (modifier bits 2..5 are ignored).
    // Vertical only (bit 1 clear): 64 = up, 65 = down.
    if cb & 0xC0 == 0x40 && cb & 0b10 == 0 {
        Some(cb & 1 == 0)
    } else {
        None
    }
}

/// The arrow-key escape an app expects, in SS3 form when application-cursor-keys
/// (DECCKM) is active — used to drive alt-screen pagers from the wheel.
fn arrow_seq(up: bool, app_cursor: bool) -> &'static [u8] {
    match (up, app_cursor) {
        (true, false) => b"\x1b[A",
        (false, false) => b"\x1b[B",
        (true, true) => b"\x1bOA",
        (false, true) => b"\x1bOB",
    }
}

/// An input event from the user's terminal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientInput {
    /// Raw keystroke bytes to forward to the remote shell.
    Keys(Vec<u8>),
    /// A complete SGR mouse report (`ESC [ < … M/m`) read from the local
    /// terminal. `run_client` routes it: when the remote app reads the mouse
    /// (vim, tmux, htop…) the report forwards verbatim; at the shell prompt —
    /// where the client forces wheel capture — wheel notches drive mosh's
    /// scrollback and clicks are swallowed; on a remote alt-screen app that
    /// does not read the mouse, wheel notches become arrow keys for it.
    Mouse(Vec<u8>),
    /// The local terminal was resized.
    Resize { cols: u16, rows: u16 },
    /// Force a full repaint of the current screen (e.g. after resuming from
    /// suspend, where the real terminal's contents were lost / changed).
    Redraw,
    /// Scroll one page up into the server-held scrollback history.
    ScrollUp,
    /// Scroll one page back down toward the live screen (exits scrollback at 0).
    ScrollDown,
    /// A scrollback *key* (Shift-Up / Shift-Down): scroll mosh's history when the
    /// user is at the shell prompt, but — since full-screen apps (vim, etc.) may
    /// bind Shift-Arrow themselves — pass it through to the app when one is on the
    /// alternate screen or reading the mouse. `passthrough` is the raw bytes to
    /// forward in that case. (Shift-PageUp/Down use [`ScrollUp`]/[`ScrollDown`],
    /// which always scroll.)
    ScrollKey { up: bool, passthrough: Vec<u8> },
    /// The user detached (e.g. Ctrl-]): begin a clean shutdown.
    Detach,
    /// Toggle the network/prediction status bar (Ctrl-^ u).
    ToggleStats,
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
/// * `title_prefix` is a client-owned label prepended to every emitted window
///   title (empty = the historical passthrough behavior; see [`new_frame`]).
#[allow(clippy::too_many_arguments)] // session entry point: discrete wired-in pieces
pub async fn run_client<T: Transport>(
    transport: Arc<T>,
    cols: u16,
    rows: u16,
    clock: Arc<dyn Clock>,
    predict: PredictMode,
    history: Option<Arc<dyn HistoryFetcher>>,
    session: Option<String>,
    title_prefix: String,
    mut input: mpsc::Receiver<ClientInput>,
    output: mpsc::UnboundedSender<Vec<u8>>,
) {
    // The driver owns the transport for the session; keep a cloned `Arc` so the
    // status bar can read its loss counters / peer address (both `&self`).
    let (driver, handle) = Driver::<T, UserStream, Screen>::with(
        transport.clone(),
        clock.clone(),
        SspConfig::default().with_env_overrides(),
    );
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

    // Status bar (Ctrl-^ u): when on, a reverse-video top row shows live link +
    // prediction health. `loss_window` samples the transport's cumulative
    // (sent, lost) packet counters on the periodic tick; the displayed loss rate
    // is the delta across the window, so it reflects the last [`LOSS_WINDOW_MS`]
    // rather than a lifetime average. Sampled even while the bar is off, so it has
    // data the moment it's toggled on.
    let mut stats_on = false;
    let mut loss_window: Vec<(u64, u64, u64)> = Vec::new();

    // Scrollback state: when `scroll_offset > 0` the client is paused in history,
    // showing `scroll_view` (the last fetched window) instead of the live screen;
    // live updates still arrive but don't disturb the view.
    let mut scroll_offset: u32 = 0;
    let mut scroll_view: Option<Screen> = None;
    // The scroll position is anchored to a *fixed point in the buffer* — the
    // viewport's top row measured as lines above the oldest retained line
    // (`scroll_anchor`) — not to the live top row. Output arriving while the user
    // is scrolled grows the buffer at the *bottom*, so a live-edge-relative offset
    // would slide the view out from under them (and strand the rows just above the
    // live screen). `scroll_hist` is the history depth at the last fetch, used to
    // convert the anchor back into the `top_above` the protocol speaks against the
    // current (possibly grown) buffer. Both are only meaningful while scrolled.
    let mut scroll_anchor: u32 = 0;
    let mut scroll_hist: u32 = 0;

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
                // The stall banner takes the top row when the link is silent;
                // otherwise the status bar (when toggled on) gets it. The two never
                // share the row — a stalled link is the more urgent message and
                // already reports "last contact".
                match mish_terminal::notification::stalled_overlay(&predicted, silent_secs) {
                    Some(stalled) => stalled,
                    None if stats_on => {
                        let stats = LinkStats {
                            session: session.clone(),
                            rtt_ms: handle.srtt_ms(),
                            loss: window_loss(&loss_window),
                            prediction: engine.accuracy(now),
                            predicting: engine.is_showing(),
                            glitchy: engine.is_glitchy(),
                            predict_mode: engine.mode(),
                            peer: transport.peer_addr(),
                            silent_secs,
                        };
                        mish_terminal::statusbar::status_bar_overlay(&predicted, &stats)
                            .unwrap_or(predicted)
                    }
                    None => predicted,
                }
            };
            // Wheel routing depends on where the remote is:
            //
            // At the shell prompt (primary screen, no mouse tracking) force SGR
            // button reporting on the local terminal so wheel notches arrive as
            // reports we route to mosh's server-side scrollback. Leaving the
            // wheel "native" doesn't work there: the client itself sits on the
            // local alternate screen, where the terminal has no scrollback to
            // scroll — and kitty unconditionally fakes wheel-as-arrow-keys on
            // the alt screen (it does not implement DECSET 1007), which the
            // shell reads as command-history navigation. Alternate-scroll is
            // pinned off for terminals that do honor 1007. The cost is that
            // click-drag selection at the prompt needs the terminal's override
            // modifier (usually Shift).
            //
            // A remote full-screen app keeps its exact modes: if it reads the
            // mouse its event encoding round-trips untouched, and if it doesn't
            // (less, plain vim) the terminal's alternate-scroll — or our
            // replication of it in the Mouse arm — turns notches into arrow
            // keys the app itself handles.
            if shown.mouse_mode == 0 && !shown.alt_screen {
                shown.mouse_mode = MOUSE_CLICK | MOUSE_SGR;
                shown.alternate_scroll = false;
            }
            let frame = new_frame(&painted, &shown, painted_once, &title_prefix);
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
            _ = tick.tick() => {
                // Sample the transport's loss counters into the rolling window
                // (cheap; done even when the bar is off so it's warm on toggle).
                if let Some(counters) = transport.loss_counters() {
                    let now = clock.now_ms();
                    loss_window.push((now, counters.0, counters.1));
                    let cutoff = now.saturating_sub(LOSS_WINDOW_MS);
                    loss_window.retain(|&(t, _, _)| t >= cutoff);
                }
                repaint!();
            }
            inp = input.recv() => {
                // Leaving scrollback: drop the history view and force a full
                // repaint of the live screen on the next `repaint!`.
                macro_rules! exit_scroll {
                    () => {{
                        if scroll_offset != 0 || scroll_view.is_some() {
                            scroll_offset = 0;
                            scroll_anchor = 0;
                            scroll_view = None;
                            painted_once = false;
                        }
                    }};
                }
                // Render the scrollback window whose top row sits `$from_oldest`
                // lines above the oldest retained line — a *buffer-relative*
                // position that stays put as new output grows the buffer. We learn
                // the current history depth from the fetch and convert the anchor
                // into a `top_above` request, refetching once if the buffer grew or
                // shrank since we last looked (so a live-edge-relative `top_above`
                // never strands content). At the live edge (`top == 0`) we leave
                // scrollback.
                macro_rules! scroll_to_anchor {
                    ($from_oldest:expr) => {{
                        if let Some(h) = &history {
                            let want = $from_oldest;
                            // Provisional request from the last known depth; the
                            // response carries the true depth so we can correct.
                            let prov = scroll_hist.saturating_sub(want);
                            if let Some(resp) = h.fetch(prov, rows).await {
                                let hist = resp.history_size;
                                let anchor = want.min(hist);
                                let top = hist.saturating_sub(anchor);
                                let resp = if top != prov {
                                    h.fetch(top, rows).await.unwrap_or(resp)
                                } else {
                                    resp
                                };
                                scroll_hist = hist;
                                if top == 0 {
                                    exit_scroll!();
                                    repaint!();
                                } else {
                                    scroll_anchor = anchor;
                                    scroll_offset = top;
                                    scroll_view = Some(history_screen(&resp, cols, rows, top));
                                    painted_once = false;
                                    repaint!();
                                }
                            }
                        }
                    }};
                }
                // Scroll one page toward older output. Entering scrollback shows
                // the page just above the live top and pins it to the buffer;
                // subsequent moves walk the buffer-relative anchor.
                macro_rules! scroll_up {
                    () => {{
                        let page = rows.max(1) as u32;
                        if scroll_view.is_none() {
                            if let Some(h) = &history {
                                if let Some(resp) = h.fetch(page, rows).await {
                                    let hist = resp.history_size;
                                    let top = page.min(hist);
                                    if top > 0 {
                                        let resp = if top != page {
                                            h.fetch(top, rows).await.unwrap_or(resp)
                                        } else {
                                            resp
                                        };
                                        scroll_hist = hist;
                                        scroll_anchor = hist.saturating_sub(top);
                                        scroll_offset = top;
                                        scroll_view = Some(history_screen(&resp, cols, rows, top));
                                        painted_once = false;
                                        repaint!();
                                    }
                                }
                            }
                        } else {
                            scroll_to_anchor!(scroll_anchor.saturating_sub(page));
                        }
                    }};
                }
                // Scroll one page back toward the live screen; at the bottom,
                // leave scrollback entirely.
                macro_rules! scroll_down {
                    () => {{
                        if scroll_view.is_some() {
                            let page = rows.max(1) as u32;
                            scroll_to_anchor!(scroll_anchor.saturating_add(page));
                        }
                    }};
                }
                match inp {
                    Some(ClientInput::Keys(b)) => {
                        // Any keystroke returns to the live screen and is forwarded.
                        exit_scroll!();
                        let press_ms = clock.now_ms();
                        stream.push_keystroke(b.clone());
                        handle.set_local(stream.clone());
                        let idx = stream.total();
                        // Speculatively echo the keystroke immediately.
                        engine.new_user_bytes(&b, &server_screen, idx, press_ms);
                        repaint!();
                        // Perf (`--perf-log`): record keypress→display latency. A
                        // no-op without the flag; when on, whether the key is being
                        // locally echoed *now* decides response ≈ 0 (predicted) vs
                        // the server round-trip (resolved later in the ack arm).
                        if crate::perf::enabled() {
                            let shown = engine.displaying_input(idx);
                            crate::perf::on_keystroke(idx, press_ms, shown, b.len());
                        }
                    }
                    Some(ClientInput::Resize { cols, rows }) => {
                        exit_scroll!();
                        stream.push_resize(cols, rows);
                        handle.set_local(stream.clone());
                    }
                    // Keyboard scroll (Shift-PageUp/Down): one page up/down.
                    Some(ClientInput::ScrollUp) => scroll_up!(),
                    Some(ClientInput::ScrollDown) => scroll_down!(),
                    // Shift-Up / Shift-Down: scroll mosh's history at the shell
                    // prompt, but hand the key to a full-screen app (which may use
                    // Shift-Arrow itself) when one is active, so we never swallow
                    // its input.
                    Some(ClientInput::ScrollKey { up, passthrough }) => {
                        if server_screen.alt_screen || server_screen.mouse_mode != 0 {
                            exit_scroll!();
                            stream.push_keystroke(passthrough.clone());
                            handle.set_local(stream.clone());
                            engine.new_user_bytes(
                                &passthrough,
                                &server_screen,
                                stream.total(),
                                clock.now_ms(),
                            );
                            repaint!();
                        } else if up {
                            scroll_up!();
                        } else {
                            scroll_down!();
                        }
                    }
                    // A mouse report from the local terminal. Route by what the
                    // remote app wants and where it is:
                    Some(ClientInput::Mouse(seq)) => {
                        if server_screen.mouse_mode != 0 {
                            // The app reads the mouse itself (vim, tmux, …):
                            // forward the report verbatim. Not a keystroke, so
                            // don't predict-echo it.
                            exit_scroll!();
                            stream.push_keystroke(seq);
                            handle.set_local(stream.clone());
                            repaint!();
                        } else if let Some(up) = sgr_wheel(&seq) {
                            if server_screen.alt_screen {
                                // Alt-screen pager (less, man…) with no mouse
                                // mode: replicate alternate-scroll by feeding it
                                // arrow keys, so it scrolls its own content
                                // rather than us hijacking the wheel.
                                let mut keys = Vec::new();
                                for _ in 0..WHEEL_STEP_LINES {
                                    keys.extend_from_slice(arrow_seq(
                                        up,
                                        server_screen.app_cursor_keys,
                                    ));
                                }
                                exit_scroll!();
                                stream.push_keystroke(keys);
                                handle.set_local(stream.clone());
                                repaint!();
                            } else if up {
                                scroll_up!();
                            } else {
                                scroll_down!();
                            }
                        }
                        // Non-wheel mouse events (clicks/drags) at the prompt
                        // mean nothing to the shell — swallow them.
                    }
                    // Force a full repaint from scratch (resume-from-suspend): the
                    // real terminal lost our painted state, so re-emit the whole
                    // screen rather than an incremental diff against `painted`.
                    Some(ClientInput::Redraw) => {
                        painted_once = false;
                        repaint!();
                    }
                    // Toggle the status bar. Force a full repaint so the row it
                    // occupies (or vacates) is rewritten cleanly.
                    Some(ClientInput::ToggleStats) => {
                        stats_on = !stats_on;
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
                let now = clock.now_ms();
                server_screen = remote.borrow_and_update().clone();
                // Validate/cull predictions against the freshly-confirmed screen.
                engine.new_server_screen(&server_screen, now);
                // Perf: finalize any keystrokes this screen confirms (no-op
                // without --perf-log). `echo_ack` is the server's applied-input
                // count, so all pending keys with idx <= it round-tripped by now.
                crate::perf::on_ack(server_screen.echo_ack, now);
                repaint!();
            }
        }
    }

    // Flush any displayed-but-unconfirmed keystrokes to the perf log before we
    // tear down (no-op without --perf-log).
    crate::perf::finish();

    // Clean shutdown: ask the peer to close, then wait briefly for the driver to
    // finish the handshake.
    tracing::info!(target: "mish::client", "client: session loop ended; finalizing shutdown handshake");
    handle.shutdown();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), driver_task).await;
    tracing::info!(target: "mish::client", "client: shutdown complete");
}

#[cfg(test)]
mod tests {
    use super::{arrow_seq, sgr_wheel};

    #[test]
    fn sgr_wheel_decodes_vertical_notches() {
        assert_eq!(sgr_wheel(b"\x1b[<64;5;5M"), Some(true)); // wheel up
        assert_eq!(sgr_wheel(b"\x1b[<65;5;5M"), Some(false)); // wheel down
                                                              // Modifier bits (here ctrl = +16) don't change the direction.
        assert_eq!(sgr_wheel(b"\x1b[<80;5;5M"), Some(true));
        assert_eq!(sgr_wheel(b"\x1b[<81;5;5M"), Some(false));
    }

    #[test]
    fn sgr_wheel_rejects_non_wheel_events() {
        assert_eq!(sgr_wheel(b"\x1b[<0;5;5M"), None); // left button press
        assert_eq!(sgr_wheel(b"\x1b[<0;5;5m"), None); // release
        assert_eq!(sgr_wheel(b"\x1b[<66;5;5M"), None); // horizontal wheel left
        assert_eq!(sgr_wheel(b"\x1b[<64;5;5m"), None); // a wheel "release" isn't a notch
        assert_eq!(sgr_wheel(b"\x1b[A"), None); // not a mouse report at all
        assert_eq!(sgr_wheel(b"\x1b[<garbage M"), None);
    }

    #[test]
    fn arrow_seq_respects_app_cursor_keys() {
        assert_eq!(arrow_seq(true, false), b"\x1b[A");
        assert_eq!(arrow_seq(false, false), b"\x1b[B");
        assert_eq!(arrow_seq(true, true), b"\x1bOA");
        assert_eq!(arrow_seq(false, true), b"\x1bOB");
    }
}
