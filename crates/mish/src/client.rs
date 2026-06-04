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
    /// The user detached (e.g. Ctrl-]): begin a clean shutdown.
    Detach,
}

/// Run a client session until input ends or the peer leaves.
///
/// * `input` yields [`ClientInput`] from the user's terminal.
/// * `output` receives the bytes to write to the user's terminal (a full-frame
///   ANSI repaint per remote screen update).
pub async fn run_client<T: Transport>(
    transport: Arc<T>,
    cols: u16,
    rows: u16,
    clock: Arc<dyn Clock>,
    predict: PredictMode,
    mut input: mpsc::Receiver<ClientInput>,
    output: mpsc::UnboundedSender<Vec<u8>>,
) {
    let (driver, handle) =
        Driver::<T, UserStream, Screen>::with(transport, clock, SspConfig::default());
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

    // Emit a minimal frame from `painted` to the current predicted screen.
    macro_rules! repaint {
        () => {{
            // Keep adaptive prediction in step with the measured link latency.
            engine.set_srtt(handle.srtt_ms());
            let predicted = engine.predicted_screen(&server_screen);
            let frame = new_frame(&painted, &predicted, painted_once);
            painted = predicted;
            painted_once = true;
            if !frame.is_empty() && output.send(frame).is_err() {
                break;
            }
        }};
    }

    loop {
        tokio::select! {
            inp = input.recv() => {
                match inp {
                    Some(ClientInput::Keys(b)) => {
                        stream.push_keystroke(b.clone());
                        handle.set_local(stream.clone());
                        // Speculatively echo the keystroke immediately.
                        engine.new_user_bytes(&b, &server_screen, stream.total());
                        repaint!();
                    }
                    Some(ClientInput::Resize { cols, rows }) => {
                        stream.push_resize(cols, rows);
                        handle.set_local(stream.clone());
                    }
                    // Detach or input closed → begin a clean shutdown.
                    Some(ClientInput::Detach) | None => break,
                }
            }
            changed = remote.changed() => {
                if changed.is_err() {
                    break; // driver stopped
                }
                server_screen = remote.borrow_and_update().clone();
                // Validate/cull predictions against the freshly-confirmed screen.
                engine.new_server_screen(&server_screen);
                repaint!();
            }
        }
    }

    // Clean shutdown: ask the peer to close, then wait briefly for the driver to
    // finish the handshake.
    handle.shutdown();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), driver_task).await;
}
