//! Persistent session: keep the PTY + emulator alive across client connections
//! so a client can **detach and reattach** (the "never lose your shell" story,
//! `NEXT_FEATURES.md` #2). Unlike the one-shot [`crate::server::run_server`],
//! here the terminal state outlives any single QUIC connection.
//!
//! The trick: the PTY-output → emulator **pump** runs forever (even with no
//! client attached), so the screen stays current during a disconnect gap.
//! [`PersistentSession::attach`] runs one client connection at a time over a
//! fresh SSP [`Driver`]; because a new connection re-syncs from scratch (both
//! cores start fresh → the first diff is a full repaint), reattaching a client
//! is automatically a full state resync — no special replay path needed.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use mish_ssp::clock::Clock;
use mish_ssp::core::SspConfig;
use mish_ssp::session::{Driver, Session};
use mish_ssp::transport::Transport;
use mish_terminal::emulator::Emulator;
use mish_terminal::screen::Screen;
use mish_terminal::user::{UserEvent, UserStream};
use tokio::sync::{mpsc, watch};

use crate::server::PtyControl;

/// The role a client attachment plays in a (possibly **shared**, multi-client)
/// session. The single read-write **owner** drives the PTY and its geometry; any
/// number of read-only **viewers** watch the same screen but can't type into it
/// (`NEXT_FEATURES.md` #3). A non-shared session always attaches as [`Owner`].
///
/// [`Owner`]: Role::Owner
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Read-write: this client's keystrokes and resizes reach the shared PTY and
    /// emulator. There is at most one owner at a time.
    Owner,
    /// Read-only viewer: keystrokes and resizes are dropped (never reach the
    /// shared shell). The viewer's reported geometry is used only to crop the
    /// published screen to its terminal ("owner drives, viewers clip").
    Viewer,
}

/// Why an [`PersistentSession::attach`] returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttachEnd {
    /// The client went away (connection lost or idle timeout). The session is
    /// still alive — loop back to `accept()` and wait for a reattach.
    Disconnected,
    /// The child process exited (the shell quit). The session is over for good;
    /// the attached client (if any) was told via the SSP shutdown handshake.
    ChildExited,
}

/// A terminal session whose PTY + emulator persist across client connections.
pub struct PersistentSession {
    emu: Arc<Mutex<Emulator>>,
    pty_input: mpsc::UnboundedSender<PtyControl>,
    clock: Arc<dyn Clock>,
    /// Bumped by the pump on each emulator change, so an attached client repaints.
    screen_rx: watch::Receiver<u64>,
    /// Set true when the child exits (the pump's PTY-output stream ended).
    done_rx: watch::Receiver<bool>,
    pump: tokio::task::JoinHandle<()>,
}

impl Drop for PersistentSession {
    fn drop(&mut self) {
        // Stop feeding once the session is no longer needed.
        self.pump.abort();
    }
}

impl PersistentSession {
    /// Start the persistent pump: feed child output into `emu` forever, draining
    /// host answerbacks back to the child, and signalling screen changes / child
    /// exit. `emu` is the shared emulator (a scrollback server may also read it).
    pub fn spawn(
        emu: Arc<Mutex<Emulator>>,
        clock: Arc<dyn Clock>,
        mut pty_output: mpsc::Receiver<Vec<u8>>,
        pty_input: mpsc::UnboundedSender<PtyControl>,
    ) -> Self {
        let (screen_tx, screen_rx) = watch::channel(0u64);
        let (done_tx, done_rx) = watch::channel(false);
        let pump_emu = emu.clone();
        let pump_input = pty_input.clone();
        let pump = tokio::spawn(async move {
            let mut seq = 0u64;
            while let Some(bytes) = pty_output.recv().await {
                {
                    let mut e = pump_emu.lock().unwrap();
                    e.feed(&bytes);
                    // Host answerbacks (DA/DSR/CPR/OSC color/size) must go back to
                    // the child or programs that probe the terminal hang.
                    let reply = e.take_answerback();
                    if !reply.is_empty() && pump_input.send(PtyControl::Input(reply)).is_err() {
                        break;
                    }
                }
                seq = seq.wrapping_add(1);
                let _ = screen_tx.send(seq);
            }
            // PTY output ended → the child exited.
            let _ = done_tx.send(true);
        });
        Self {
            emu,
            pty_input,
            clock,
            screen_rx,
            done_rx,
            pump,
        }
    }

    /// Snapshot the current screen with this attachment's echo ack.
    fn screen(&self, processed: u64) -> Screen {
        let mut s = self.emu.lock().unwrap().snapshot();
        s.echo_ack = processed;
        s
    }

    /// The screen to publish to one attachment: the live snapshot for an owner;
    /// for a viewer, cropped/padded to its own reported geometry ("owner drives,
    /// viewers clip"). Until a viewer has reported its size (`view_geom == None`)
    /// it gets the owner geometry, corrected on its first resize.
    fn screen_for(&self, processed: u64, role: Role, view_geom: Option<(u16, u16)>) -> Screen {
        let s = self.screen(processed);
        match (role, view_geom) {
            (Role::Viewer, Some((cols, rows))) => s.resized_view(cols, rows),
            _ => s,
        }
    }

    /// Run one client connection over `transport` until it disconnects or the
    /// child exits. The (re)attaching client gets a full repaint of the current
    /// screen automatically (a fresh SSP session re-syncs from scratch). Takes
    /// `Arc<Self>` so it can be spawned concurrently (the binary loops over it).
    /// `cancel` lets the caller **preempt** this attachment: when it resolves,
    /// `attach` returns [`AttachEnd::Disconnected`] promptly without waiting out
    /// `network_timeout`. The binary fires it when a *new* connection arrives, so
    /// a reattach (e.g. after a hard drop that never closed the old connection)
    /// takes over immediately instead of blocking for up to 5 minutes. Pass
    /// `std::future::pending()` to opt out.
    ///
    /// `role` is the client's access level. [`Role::Owner`] (the only role a
    /// non-shared session uses) forwards keystrokes/resizes to the shared PTY;
    /// [`Role::Viewer`] drops them and only watches, with the published screen
    /// cropped to the viewer's own terminal size.
    pub async fn attach<T: Transport>(
        self: Arc<Self>,
        transport: Arc<T>,
        network_timeout: Option<Duration>,
        cancel: impl std::future::Future<Output = ()> + Send,
        role: Role,
    ) -> AttachEnd {
        let (driver, handle) =
            Driver::<T, Screen, UserStream>::with(transport, self.clock.clone(), SspConfig::default());
        let driver_task = driver.spawn();

        // How many of *this* client's input events we've applied (its echo ack).
        let mut processed: u64 = 0;
        // A viewer's last reported terminal size, used to crop the published
        // screen to its geometry. `None` until its first resize arrives.
        let mut view_geom: Option<(u16, u16)> = None;
        // Initial publish → full repaint of the current screen to the new client.
        handle.set_local(self.screen_for(processed, role, view_geom));

        let mut remote = handle.subscribe_remote();
        let mut screen_rx = self.screen_rx.clone();
        let mut done_rx = self.done_rx.clone();

        // Tidy close if the child already exited before this client attached.
        if *done_rx.borrow() {
            handle.shutdown();
            let _ = tokio::time::timeout(Duration::from_secs(2), driver_task).await;
            return AttachEnd::ChildExited;
        }

        tokio::pin!(cancel);
        let mut last_heard = tokio::time::Instant::now();
        loop {
            let idle = network_timeout.map(|t| tokio::time::sleep_until(last_heard + t));
            tokio::select! {
                // A new connection is taking over (see the `cancel` doc above).
                // Drop this attachment now — don't wait out the idle timeout — and
                // abort its now-orphaned driver. The session lives on for the
                // newcomer, so this is a Disconnected, not a ChildExited.
                _ = &mut cancel => {
                    tracing::info!(target: "mish::persist", "attachment preempted by a new connection");
                    driver_task.abort();
                    return AttachEnd::Disconnected;
                }
                _ = async { idle.unwrap().await }, if network_timeout.is_some() => {
                    // Client quiet too long: end this attachment but keep the
                    // session alive for a later reattach. Abort the driver, whose
                    // connection is gone.
                    tracing::info!(target: "mish::persist", "client idle past network timeout; awaiting reattach");
                    driver_task.abort();
                    return AttachEnd::Disconnected;
                }
                _ = done_rx.changed() => {
                    if *done_rx.borrow() {
                        tracing::info!(target: "mish::persist", "child exited; shutting down attached client");
                        handle.shutdown();
                        let _ = tokio::time::timeout(Duration::from_secs(2), driver_task).await;
                        return AttachEnd::ChildExited;
                    }
                }
                res = screen_rx.changed() => {
                    if res.is_err() {
                        // Pump gone (child exited and the channel dropped).
                        return AttachEnd::ChildExited;
                    }
                    let screen = self.screen_for(processed, role, view_geom);
                    handle.set_local(screen);
                }
                changed = remote.changed() => {
                    if changed.is_err() {
                        // Driver stopped — the connection is gone. Keep the
                        // session for reattach. (The driver has already exited;
                        // abort is a harmless no-op that keeps every Disconnected
                        // path symmetric.)
                        tracing::info!(target: "mish::persist", "client connection dropped; awaiting reattach");
                        driver_task.abort();
                        return AttachEnd::Disconnected;
                    }
                    last_heard = tokio::time::Instant::now();
                    let stream = remote.borrow_and_update().clone();
                    {
                        let mut e = self.emu.lock().unwrap();
                        for ev in stream.events_since(processed) {
                            match ev {
                                // An owner's keystrokes reach the shared shell; a
                                // viewer's are dropped (read-only). Either way the
                                // event is consumed below (`processed`), so a
                                // viewer's local prediction culls promptly rather
                                // than resending forever.
                                UserEvent::Keystroke(b) => {
                                    if role == Role::Owner {
                                        let _ = self.pty_input.send(PtyControl::Input(b.clone()));
                                    }
                                }
                                // The owner drives the PTY geometry; a viewer only
                                // records its own size to crop the screen it sees.
                                UserEvent::Resize { cols, rows } => match role {
                                    Role::Owner => {
                                        let _ = self
                                            .pty_input
                                            .send(PtyControl::Resize { cols: *cols, rows: *rows });
                                        e.resize(*cols, *rows);
                                    }
                                    Role::Viewer => view_geom = Some((*cols, *rows)),
                                },
                            }
                        }
                        processed = stream.total();
                    }
                    handle.set_local(self.screen_for(processed, role, view_geom));
                }
            }
        }
    }
}
