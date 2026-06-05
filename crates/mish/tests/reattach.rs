//! Session persistence + reattach (NEXT_FEATURES.md #2): a `PersistentSession`
//! keeps the PTY + emulator alive across client connections, so a client can
//! detach and a *new* connection reattaches to the same live session and
//! re-syncs the full current screen — including output produced while no client
//! was attached.

use std::sync::Arc;
use std::time::Duration;

use mish::persist::{AttachEnd, PersistentSession};
use mish::server::PtyControl;
use mish_ssp::clock::{Clock, SystemClock};
use mish_ssp::core::SspConfig;
use mish_ssp::memory::{self, MemoryTransport};
use mish_ssp::session::{Driver, Session, SessionError, SessionHandle};
use mish_terminal::emulator::Emulator;
use mish_terminal::screen::Screen;
use mish_terminal::user::UserStream;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

/// A minimal client over the in-memory transport: a Driver that syncs the
/// server's `Screen`. `disconnect` aborts it (dropping the transport), which the
/// server sees as a lost connection.
struct Client {
    remote: watch::Receiver<Screen>,
    task: JoinHandle<Result<(), SessionError>>,
    _handle: SessionHandle<UserStream, Screen>,
}

impl Client {
    fn spawn(t: MemoryTransport, clock: Arc<dyn Clock>) -> Self {
        let (driver, handle) =
            Driver::<MemoryTransport, UserStream, Screen>::with(Arc::new(t), clock, SspConfig::default());
        let task = driver.spawn();
        // Report initial geometry so the server has a remote state to process.
        let mut s = UserStream::new();
        s.push_resize(80, 24);
        handle.set_local(s);
        let remote = handle.subscribe_remote();
        Self {
            remote,
            task,
            _handle: handle,
        }
    }

    fn disconnect(self) {
        self.task.abort();
    }

    /// Wait until the synced screen contains `needle`.
    async fn expect_contains(&mut self, needle: &str) {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                {
                    let s = self.remote.borrow_and_update();
                    if s.to_lines().join("\n").contains(needle) {
                        return;
                    }
                }
                if self.remote.changed().await.is_err() {
                    panic!("client remote closed before seeing {needle:?}");
                }
            }
        })
        .await
        .unwrap_or_else(|_| panic!("client never saw {needle:?}"));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn session_persists_across_reattach() {
    let (pty_out_tx, pty_out_rx) = mpsc::channel::<Vec<u8>>(64);
    let (pty_in_tx, _pty_in_rx) = mpsc::unbounded_channel::<PtyControl>();
    let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
    let emu = Emulator::shared(80, 24);
    let session = Arc::new(PersistentSession::spawn(
        emu.clone(),
        clock.clone(),
        pty_out_rx,
        pty_in_tx,
    ));
    let net = Some(Duration::from_secs(300));

    // Output produced before any client attaches (lands in the emulator).
    pty_out_tx.send(b"LINE_ONE\r\n".to_vec()).await.unwrap();

    // --- Client A attaches: must see the pre-attach output (full resync). ---
    let (sa, ca) = memory::pair();
    let a_end = tokio::spawn(session.clone().attach(Arc::new(sa), net));
    let mut a = Client::spawn(ca, clock.clone());
    a.expect_contains("LINE_ONE").await;

    // Output while A is attached.
    pty_out_tx.send(b"LINE_TWO\r\n".to_vec()).await.unwrap();
    a.expect_contains("LINE_TWO").await;

    // --- A detaches; the session stays alive (Disconnected, not ChildExited). ---
    a.disconnect();
    assert_eq!(
        a_end.await.unwrap(),
        AttachEnd::Disconnected,
        "a detach keeps the session alive for reattach"
    );

    // Output during the gap (no client) still feeds the emulator.
    pty_out_tx.send(b"LINE_THREE\r\n".to_vec()).await.unwrap();

    // --- Client B reattaches on a fresh connection: must see ALL three lines. ---
    let (sb, cb) = memory::pair();
    let b_end = tokio::spawn(session.clone().attach(Arc::new(sb), net));
    let mut b = Client::spawn(cb, clock.clone());
    b.expect_contains("LINE_ONE").await; // survived the whole time
    b.expect_contains("LINE_THREE").await; // produced during the disconnect gap

    b.disconnect();
    let _ = b_end.await;
}
