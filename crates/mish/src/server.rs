//! The server session loop: bridges a child process's PTY to the SSP layer.
//!
//! The server synchronizes `Screen` (out) and receives `UserStream` (in):
//! it is an `SspCore<Screen, UserStream>`. This function is **generic over the
//! transport and decoupled from the real PTY via channels**, so it can be tested
//! over the in-memory transport with a fake PTY (see `tests/loopback.rs`). The
//! binary wires a real `portable-pty` child into these channels.

use std::sync::Arc;

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
/// * `pty_output` yields raw bytes produced by the child process.
/// * `pty_input` receives [`PtyControl`] messages to apply to the child.
pub async fn run_server<T: Transport>(
    transport: Arc<T>,
    cols: u16,
    rows: u16,
    clock: Arc<dyn Clock>,
    network_timeout: Option<std::time::Duration>,
    mut pty_output: mpsc::Receiver<Vec<u8>>,
    pty_input: mpsc::UnboundedSender<PtyControl>,
) {
    let (driver, handle) =
        Driver::<T, Screen, UserStream>::with(transport, clock, SspConfig::default());
    driver.spawn();

    let mut emu = Emulator::new(cols, rows);
    // How many user events we've already applied to the PTY (the echo ack).
    let mut processed: u64 = 0;
    let publish = |emu: &Emulator, processed: u64| {
        let mut screen = emu.snapshot();
        screen.echo_ack = processed;
        screen
    };
    handle.set_local(publish(&emu, processed));

    let mut remote = handle.subscribe_remote();
    // Idle watchdog: if we don't hear from the client (no inbound state, not
    // even a keepalive) within network_timeout, shut the session down — mosh's
    // MOSH_SERVER_NETWORK_TMOUT, which keeps orphaned servers from lingering.
    let mut last_heard = tokio::time::Instant::now();

    loop {
        let idle = network_timeout.map(|t| tokio::time::sleep_until(last_heard + t));
        tokio::select! {
            _ = async { idle.unwrap().await }, if network_timeout.is_some() => {
                // No client traffic within the timeout window.
                return;
            }
            // Child produced output → feed the emulator, publish the new screen.
            out = pty_output.recv() => {
                match out {
                    Some(bytes) => {
                        emu.feed(&bytes);
                        handle.set_local(publish(&emu, processed));
                    }
                    None => break, // child exited
                }
            }
            // Client sent new input → apply the new events to the PTY.
            changed = remote.changed() => {
                if changed.is_err() {
                    break; // driver stopped
                }
                // Heard from the client (input or keepalive) — reset the watchdog.
                last_heard = tokio::time::Instant::now();
                let stream = remote.borrow_and_update().clone();
                for ev in stream.events_since(processed) {
                    match ev {
                        UserEvent::Keystroke(b) => {
                            if pty_input.send(PtyControl::Input(b.clone())).is_err() {
                                return;
                            }
                        }
                        UserEvent::Resize { cols, rows } => {
                            if pty_input
                                .send(PtyControl::Resize { cols: *cols, rows: *rows })
                                .is_err()
                            {
                                return;
                            }
                            emu.resize(*cols, *rows);
                        }
                    }
                }
                processed = stream.total();
                // Publish the new echo ack (and any geometry change) so the
                // client can validate its predictions.
                handle.set_local(publish(&emu, processed));
            }
        }
    }
}
