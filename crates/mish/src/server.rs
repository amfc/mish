//! The server session loop: bridges a child process's PTY to the SSP layer.
//!
//! The server synchronizes `Screen` (out) and receives `UserStream` (in):
//! it is an `SspCore<Screen, UserStream>`. This function is **generic over the
//! transport and decoupled from the real PTY via channels**, so it can be tested
//! over the in-memory transport with a fake PTY (see `tests/loopback.rs`). The
//! binary wires a real `portable-pty` child into these channels.

use std::sync::{Arc, Mutex};

use mish_ssp::clock::Clock;
use mish_ssp::core::SspConfig;
use mish_ssp::session::{Driver, Session};
use mish_ssp::transport::Transport;
use mish_terminal::emulator::Emulator;
use mish_terminal::screen::Screen;
use mish_terminal::user::{UserEvent, UserStream};
use tokio::sync::mpsc;

/// A control message from the session to the child PTY.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PtyControl {
    /// Bytes to write to the child's input.
    Input(Vec<u8>),
    /// The client resized; resize the child's PTY.
    Resize { cols: u16, rows: u16 },
}

/// Run a server session until the PTY closes (child exits) or the peer leaves.
///
/// * `emu` is the shared emulator the server feeds; it is held in an
///   `Arc<Mutex<…>>` so a concurrent **scrollback** server
///   ([`crate::scrollback::serve_history`]) can read its history. Locks here are
///   always brief and never span an `.await`, so there's no contention with the
///   live session loop.
/// * `pty_output` yields raw bytes produced by the child process.
/// * `pty_input` receives [`PtyControl`] messages to apply to the child.
pub async fn run_server<T: Transport>(
    transport: Arc<T>,
    emu: Arc<Mutex<Emulator>>,
    clock: Arc<dyn Clock>,
    network_timeout: Option<std::time::Duration>,
    mut pty_output: mpsc::Receiver<Vec<u8>>,
    pty_input: mpsc::UnboundedSender<PtyControl>,
) {
    let (driver, handle) =
        Driver::<T, Screen, UserStream>::with(transport, clock, SspConfig::default());
    let driver_task = driver.spawn();
    tracing::info!(target: "mish::server", "server session loop started");

    // How many user events we've already applied to the PTY (the echo ack).
    let mut processed: u64 = 0;
    let publish = |emu: &Emulator, processed: u64| {
        let mut screen = emu.snapshot();
        screen.echo_ack = processed;
        screen
    };
    handle.set_local(publish(&emu.lock().unwrap(), processed));

    let mut remote = handle.subscribe_remote();
    // Idle watchdog: if we don't hear from the client (no inbound state, not
    // even a keepalive) within network_timeout, shut the session down — mosh's
    // MOSH_SERVER_NETWORK_TMOUT, which keeps orphaned servers from lingering.
    let mut last_heard = tokio::time::Instant::now();

    'session: loop {
        let idle = network_timeout.map(|t| tokio::time::sleep_until(last_heard + t));
        tokio::select! {
            _ = async { idle.unwrap().await }, if network_timeout.is_some() => {
                // No client traffic within the timeout window: the client is
                // unreachable, so there's no point negotiating a clean shutdown —
                // just drop the session.
                tracing::info!(target: "mish::server", "server: network timeout; dropping session");
                return;
            }
            // Child produced output → feed the emulator, publish the new screen.
            out = pty_output.recv() => {
                match out {
                    Some(bytes) => {
                        // Brief lock: feed, drain answerbacks, snapshot — all
                        // synchronous, no .await held across the guard.
                        let screen = {
                            let mut e = emu.lock().unwrap();
                            e.feed(&bytes);
                            // Host answerbacks (DA/DSR/CPR/OSC color/size replies)
                            // the child's query sequences produced must go back to
                            // its input, or programs that probe the terminal hang.
                            let reply = e.take_answerback();
                            if !reply.is_empty()
                                && pty_input.send(PtyControl::Input(reply)).is_err()
                            {
                                break 'session; // child gone
                            }
                            publish(&e, processed)
                        };
                        handle.set_local(screen);
                    }
                    None => {
                        tracing::info!(target: "mish::server", "server: pty_output closed (child exited); shutting down");
                        break 'session; // child exited
                    }
                }
            }
            // Client sent new input → apply the new events to the PTY.
            changed = remote.changed() => {
                if changed.is_err() {
                    break 'session; // driver stopped
                }
                // Heard from the client (input or keepalive) — reset the watchdog.
                last_heard = tokio::time::Instant::now();
                let stream = remote.borrow_and_update().clone();
                let screen = {
                    let mut e = emu.lock().unwrap();
                    for ev in stream.events_since(processed) {
                        match ev {
                            UserEvent::Keystroke(b) => {
                                if pty_input.send(PtyControl::Input(b.clone())).is_err() {
                                    break 'session; // child gone
                                }
                            }
                            UserEvent::Resize { cols, rows } => {
                                if pty_input
                                    .send(PtyControl::Resize { cols: *cols, rows: *rows })
                                    .is_err()
                                {
                                    break 'session; // child gone
                                }
                                e.resize(*cols, *rows);
                            }
                        }
                    }
                    processed = stream.total();
                    // Publish the new echo ack (and any geometry change) so the
                    // client can validate its predictions.
                    publish(&e, processed)
                };
                handle.set_local(screen);
            }
        }
    }

    // The child exited (e.g. the user pressed Ctrl-D / the shell quit). Tell the
    // client we're closing via the SSP SHUTDOWN handshake — mirroring the client's
    // own detach path — so it exits immediately instead of waiting out its network
    // timeout and showing "Last contact N seconds ago". Then wait briefly for the
    // driver to deliver the handshake before the runtime tears down.
    tracing::info!(target: "mish::server", "server: session loop ended; initiating shutdown handshake");
    handle.shutdown();
    let joined = tokio::time::timeout(std::time::Duration::from_secs(2), driver_task).await;
    tracing::info!(
        target: "mish::server",
        timed_out = joined.is_err(),
        "server: shutdown handshake finished; driver joined"
    );
}
