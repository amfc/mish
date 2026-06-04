//! The async session driver: glue between a [`Transport`] and an [`SspCore`].
//!
//! The protocol logic lives entirely in the sans-IO [`SspCore`]. This module is
//! the thin I/O shell mosh's `stmclient`/`mosh-server` event loops occupy: a
//! single task that selects over (a) inbound datagrams, (b) application requests
//! to change the local state, and (c) the protocol's own timer, calling
//! `core.tick()` whenever something is due and flushing the resulting
//! instructions to the wire.
//!
//! The application interacts through a cheap [`SessionHandle`] (which implements
//! the [`Session`] trait): push local states in, observe the latest remote state
//! out via a `watch` channel.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, watch};

use crate::clock::{Clock, SystemClock};
use crate::core::{SspConfig, SspCore};
use crate::frag::{Defragmenter, Fragmenter};
use crate::instruction::Instruction;
use crate::state::SyncState;
use crate::transport::{Transport, TransportError};

/// Errors that terminate a session.
#[derive(thiserror::Error, Debug)]
pub enum SessionError {
    #[error("transport closed")]
    Closed,
    #[error(transparent)]
    Transport(#[from] TransportError),
}

/// High-level, cloneable interface to a running session.
pub trait Session: Send + Sync {
    type Local: SyncState;
    type Remote: SyncState;

    /// Queue a new local state to synchronize to the peer. Returns `false` if
    /// the driver has stopped.
    fn set_local(&self, state: Self::Local) -> bool;

    /// A clone of the latest known remote state.
    fn remote(&self) -> Self::Remote;

    /// Subscribe to remote-state updates (latest-wins semantics).
    fn subscribe_remote(&self) -> watch::Receiver<Self::Remote>;
}

/// Application-side handle to a session. Cheap to clone.
pub struct SessionHandle<L: SyncState, R: SyncState> {
    local_tx: mpsc::UnboundedSender<L>,
    remote_rx: watch::Receiver<R>,
    srtt_rx: watch::Receiver<f64>,
    shutdown: Arc<tokio::sync::Notify>,
}

impl<L: SyncState, R: SyncState> Clone for SessionHandle<L, R> {
    fn clone(&self) -> Self {
        Self {
            local_tx: self.local_tx.clone(),
            remote_rx: self.remote_rx.clone(),
            srtt_rx: self.srtt_rx.clone(),
            shutdown: self.shutdown.clone(),
        }
    }
}

impl<L: SyncState + Send + Sync + 'static, R: SyncState + Send + Sync + 'static> Session
    for SessionHandle<L, R>
{
    type Local = L;
    type Remote = R;

    fn set_local(&self, state: L) -> bool {
        self.local_tx.send(state).is_ok()
    }

    fn remote(&self) -> R {
        self.remote_rx.borrow().clone()
    }

    fn subscribe_remote(&self) -> watch::Receiver<R> {
        self.remote_rx.clone()
    }
}

impl<L: SyncState, R: SyncState> SessionHandle<L, R> {
    /// Current smoothed round-trip time estimate (ms). Lets the client gate
    /// predictive echo on link latency (mosh's adaptive prediction).
    pub fn srtt_ms(&self) -> f64 {
        *self.srtt_rx.borrow()
    }

    /// Request a clean shutdown: the driver sends a SHUTDOWN handshake and ends
    /// once the peer acknowledges (or after a short grace period).
    pub fn shutdown(&self) {
        self.shutdown.notify_one();
    }

    /// Await the next change to the remote state, returning a clone. `None` once
    /// the driver has stopped.
    pub async fn remote_changed(&mut self) -> Option<R> {
        self.remote_rx.changed().await.ok()?;
        Some(self.remote_rx.borrow().clone())
    }
}

/// Owns the protocol core + transport and runs the event loop.
pub struct Driver<T: Transport, L: SyncState, R: SyncState> {
    transport: Arc<T>,
    core: SspCore<L, R>,
    clock: Arc<dyn Clock>,
    local_rx: mpsc::UnboundedReceiver<L>,
    remote_tx: watch::Sender<R>,
    srtt_tx: watch::Sender<f64>,
    shutdown: Arc<tokio::sync::Notify>,
    last_published_num: u64,
    fragmenter: Fragmenter,
    defragmenter: Defragmenter,
}

impl<T, L, R> Driver<T, L, R>
where
    T: Transport,
    L: SyncState + Send + Sync + 'static,
    R: SyncState + Send + Sync + 'static,
{
    /// Build a driver and its application handle using the system clock.
    pub fn new(transport: Arc<T>) -> (Self, SessionHandle<L, R>) {
        Self::with(transport, Arc::new(SystemClock::new()), SspConfig::default())
    }

    /// Build a driver with an injected clock and config (for tests / simulation).
    pub fn with(
        transport: Arc<T>,
        clock: Arc<dyn Clock>,
        cfg: SspConfig,
    ) -> (Self, SessionHandle<L, R>) {
        let (local_tx, local_rx) = mpsc::unbounded_channel();
        let (remote_tx, remote_rx) = watch::channel(R::new_initial());
        let now = clock.now_ms();
        let core = SspCore::with_config(now, cfg);
        let (srtt_tx, srtt_rx) = watch::channel(core.srtt_ms());
        let shutdown = Arc::new(tokio::sync::Notify::new());
        let driver = Self {
            transport,
            core,
            clock,
            local_rx,
            remote_tx,
            srtt_tx,
            shutdown: shutdown.clone(),
            last_published_num: 0,
            fragmenter: Fragmenter::new(),
            defragmenter: Defragmenter::new(),
        };
        let handle = SessionHandle {
            local_tx,
            remote_rx,
            srtt_rx,
            shutdown,
        };
        (driver, handle)
    }

    /// Spawn the driver on the current tokio runtime, returning the handle and
    /// the task's `JoinHandle`.
    pub fn spawn(self) -> tokio::task::JoinHandle<Result<(), SessionError>>
    where
        T: 'static,
    {
        tokio::spawn(self.run())
    }

    /// Run the event loop until the transport closes.
    pub async fn run(mut self) -> Result<(), SessionError> {
        // Once the application drops every handle, `local_rx` is permanently
        // closed; we must stop selecting on it or the always-ready `None` would
        // busy-loop (and, under a paused/simulated clock, wedge the whole runtime
        // by never letting it go idle).
        let mut local_open = true;
        let mut shutting_down = false;
        let mut shutdown_deadline = crate::clock::NEVER;
        loop {
            let now = self.clock.now_ms();

            // 1. Run the protocol and flush any instructions to the wire.
            for inst in self.core.tick(now) {
                self.send(inst).await?;
            }

            // 2. Publish remote-state changes to subscribers.
            self.publish_remote();

            // 3. Clean-shutdown completion: the peer acknowledged our shutdown
            //    (we sent our final ack-bearing frame in the tick above), or the
            //    grace period elapsed.
            if shutting_down && (self.core.is_shutdown_acked() || now >= shutdown_deadline) {
                return Ok(());
            }

            // 3. Sleep until the next protocol event, or until something happens.
            let wait = self.core.wait_time(self.clock.now_ms());
            let sleep = tokio::time::sleep(Duration::from_millis(
                wait.unwrap_or(3_600_000),
            ));
            tokio::pin!(sleep);

            tokio::select! {
                // Inbound datagram.
                recv = self.transport.recv() => {
                    match recv {
                        Ok(bytes) => {
                            // Reassemble fragments; a complete instruction may
                            // arrive on the last fragment of a group.
                            if let Some(payload) = self.defragmenter.push(&bytes) {
                                if let Some(inst) = Instruction::decode(&payload) {
                                    let now = self.clock.now_ms();
                                    self.core.recv(now, &inst);
                                    self.publish_remote();
                                    let _ = self.srtt_tx.send(self.core.srtt_ms());
                                    // The peer initiated shutdown — mirror it so
                                    // both sides converge to a clean close.
                                    if self.core.peer_is_shutting_down() && !shutting_down {
                                        shutting_down = true;
                                        self.core.start_shutdown();
                                        shutdown_deadline = now + 5000;
                                    }
                                }
                            }
                            // Malformed / incomplete datagrams are silently dropped.
                        }
                        Err(TransportError::Closed) => return Err(SessionError::Closed),
                        Err(_) => { /* transient: treat as a drop */ }
                    }
                }
                // Application changed the local state (only while a handle lives).
                local = self.local_rx.recv(), if local_open => {
                    match local {
                        Some(state) => self.core.set_current_state(state),
                        None => local_open = false, // handle dropped; keep serving
                    }
                }
                // Application requested a clean shutdown.
                _ = self.shutdown.notified(), if !shutting_down => {
                    shutting_down = true;
                    self.core.start_shutdown();
                    shutdown_deadline = self.clock.now_ms() + 5000;
                }
                // Protocol timer fired; loop back to tick().
                _ = &mut sleep => {}
            }
        }
    }

    async fn send(&mut self, inst: Instruction) -> Result<(), SessionError> {
        let payload = inst.encode();
        let max = self.transport.max_datagram_size();
        for fragment in self.fragmenter.fragment(&payload, max) {
            match self.transport.send(fragment).await {
                Ok(()) => {}
                Err(TransportError::Closed) => return Err(SessionError::Closed),
                // Oversize / transient send errors look like a dropped datagram
                // to the protocol, which will re-diff and try again.
                Err(_) => {}
            }
        }
        Ok(())
    }

    fn publish_remote(&mut self) {
        let num = self.core.remote_state_num();
        if num != self.last_published_num {
            self.last_published_num = num;
            // Ignore send error: no subscribers is fine.
            let _ = self.remote_tx.send(self.core.remote_state().clone());
        }
    }
}
