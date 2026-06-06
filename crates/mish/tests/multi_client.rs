//! Multi-client attach (NEXT_FEATURES.md #3): several clients share one
//! `PersistentSession` at the same time — exactly one read-write **owner** plus
//! any number of read-only **viewers**. This exercises the headless substrate:
//! both roles converge on the same screen, only the owner's keystrokes reach the
//! PTY, and a viewer with a smaller terminal sees the owner's screen cropped to
//! its own geometry ("owner drives, viewers clip").

use std::sync::Arc;
use std::time::Duration;

use mish::persist::{PersistentSession, Role};
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

/// A minimal client over the in-memory transport that can also type and resize.
struct Client {
    stream: UserStream,
    handle: SessionHandle<UserStream, Screen>,
    remote: watch::Receiver<Screen>,
    task: JoinHandle<Result<(), SessionError>>,
}

impl Client {
    fn spawn(t: MemoryTransport, clock: Arc<dyn Clock>, cols: u16, rows: u16) -> Self {
        let (driver, handle) =
            Driver::<MemoryTransport, UserStream, Screen>::with(Arc::new(t), clock, SspConfig::default());
        let task = driver.spawn();
        let mut stream = UserStream::new();
        stream.push_resize(cols, rows); // report our geometry up front
        handle.set_local(stream.clone());
        let remote = handle.subscribe_remote();
        Self {
            stream,
            handle,
            remote,
            task,
        }
    }

    /// Send keystrokes to the server.
    fn type_str(&mut self, s: &str) {
        self.stream.push_keystroke(s.as_bytes().to_vec());
        self.handle.set_local(self.stream.clone());
    }

    fn screen(&self) -> Screen {
        self.remote.borrow().clone()
    }

    /// Wait until the synced screen contains `needle`.
    async fn expect_contains(&mut self, needle: &str) {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if self.remote.borrow_and_update().to_text().contains(needle) {
                    return;
                }
                if self.remote.changed().await.is_err() {
                    panic!("client remote closed before seeing {needle:?}");
                }
            }
        })
        .await
        .unwrap_or_else(|_| panic!("client never saw {needle:?}"));
    }

    /// Wait until the synced screen reaches the given geometry.
    async fn expect_size(&mut self, cols: u16, rows: u16) {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                {
                    let s = self.remote.borrow_and_update();
                    if (s.cols, s.rows) == (cols, rows) {
                        return;
                    }
                }
                if self.remote.changed().await.is_err() {
                    panic!("client remote closed before reaching {cols}x{rows}");
                }
            }
        })
        .await
        .unwrap_or_else(|_| panic!("client never reached {cols}x{rows}"));
    }

    fn disconnect(self) {
        self.task.abort();
    }
}

/// Both an owner and a viewer attached to the same session see the same output;
/// the owner's keystrokes reach the PTY but the viewer's are dropped (read-only).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn owner_writes_viewer_is_read_only() {
    let (pty_out_tx, pty_out_rx) = mpsc::channel::<Vec<u8>>(64);
    let (pty_in_tx, mut pty_in_rx) = mpsc::unbounded_channel::<PtyControl>();
    let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
    let emu = Emulator::shared(80, 24);
    let session = Arc::new(PersistentSession::spawn(
        emu,
        clock.clone(),
        pty_out_rx,
        pty_in_tx,
    ));
    let net = Some(Duration::from_secs(300));

    // Owner + viewer attach concurrently to the one session.
    let (s_owner, c_owner) = memory::pair();
    let (s_viewer, c_viewer) = memory::pair();
    let _owner_end = tokio::spawn(session.clone().attach(
        Arc::new(s_owner),
        net,
        std::future::pending::<()>(),
        Role::Owner,
    ));
    let _viewer_end = tokio::spawn(session.clone().attach(
        Arc::new(s_viewer),
        net,
        std::future::pending::<()>(),
        Role::Viewer,
    ));
    let mut owner = Client::spawn(c_owner, clock.clone(), 80, 24);
    let mut viewer = Client::spawn(c_viewer, clock.clone(), 80, 24);

    // Shell output fans out to *both* clients (one-to-many state sync).
    pty_out_tx.send(b"SHARED_OUTPUT\r\n".to_vec()).await.unwrap();
    owner.expect_contains("SHARED_OUTPUT").await;
    viewer.expect_contains("SHARED_OUTPUT").await;

    // The viewer types first — these keystrokes must be dropped server-side.
    viewer.type_str("VIEWER_KEYS");
    // The owner types a sentinel — it must reach the PTY.
    owner.type_str("OWN");

    // Drain PTY input until the owner's sentinel arrives; assert the viewer's
    // keystrokes never appear (a viewer is read-only; its input is dropped, not
    // forwarded). Resize controls (the owner's initial geometry) are ignored here.
    let saw_owner = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match pty_in_rx.recv().await {
                Some(PtyControl::Input(bytes)) => {
                    let text = String::from_utf8_lossy(&bytes).into_owned();
                    assert!(
                        !text.contains("VIEWER_KEYS"),
                        "a viewer's keystrokes must never reach the PTY (got {text:?})"
                    );
                    if text.contains("OWN") {
                        return true;
                    }
                }
                Some(PtyControl::Resize { .. }) => {} // owner geometry; not a keystroke
                None => return false,
            }
        }
    })
    .await
    .expect("owner keystroke should reach the PTY promptly");
    assert!(saw_owner, "owner's keystroke never reached the PTY");

    // Grace window: confirm the viewer's keystrokes still haven't slipped through.
    let leaked = tokio::time::timeout(Duration::from_millis(300), async {
        while let Some(ctl) = pty_in_rx.recv().await {
            if let PtyControl::Input(bytes) = ctl {
                if String::from_utf8_lossy(&bytes).contains("VIEWER_KEYS") {
                    return true;
                }
            }
        }
        false
    })
    .await
    .unwrap_or(false);
    assert!(!leaked, "viewer keystrokes leaked to the PTY after the owner's");

    owner.disconnect();
    viewer.disconnect();
}

/// The owner drives the PTY geometry; a viewer on a smaller terminal sees the
/// owner's screen cropped to its own size, without resizing the shared shell.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn viewer_screen_is_cropped_to_its_own_size() {
    let (pty_out_tx, pty_out_rx) = mpsc::channel::<Vec<u8>>(64);
    let (pty_in_tx, _pty_in_rx) = mpsc::unbounded_channel::<PtyControl>();
    let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
    let emu = Emulator::shared(80, 24);
    let session = Arc::new(PersistentSession::spawn(
        emu,
        clock.clone(),
        pty_out_rx,
        pty_in_tx,
    ));
    let net = Some(Duration::from_secs(300));

    let (s_owner, c_owner) = memory::pair();
    let (s_viewer, c_viewer) = memory::pair();
    let _owner_end = tokio::spawn(session.clone().attach(
        Arc::new(s_owner),
        net,
        std::future::pending::<()>(),
        Role::Owner,
    ));
    let _viewer_end = tokio::spawn(session.clone().attach(
        Arc::new(s_viewer),
        net,
        std::future::pending::<()>(),
        Role::Viewer,
    ));
    // Owner is the full 80x24; the viewer's terminal is a small 40x10.
    let mut owner = Client::spawn(c_owner, clock.clone(), 80, 24);
    let mut viewer = Client::spawn(c_viewer, clock.clone(), 40, 10);

    // A 50-character line: fits the owner's 80 cols, exceeds the viewer's 40.
    let line = "X".repeat(50);
    pty_out_tx
        .send(format!("{line}\r\n").into_bytes())
        .await
        .unwrap();

    // The viewer converges on *its own* geometry (the owner's shell is untouched).
    viewer.expect_size(40, 10).await;
    owner.expect_contains(&line).await;

    let vs = viewer.screen();
    assert_eq!((vs.cols, vs.rows), (40, 10), "viewer sees its own size");
    assert_eq!(
        vs.to_lines()[0].len(),
        40,
        "the 50-char line is cropped to the viewer's 40 columns"
    );

    // The owner still sees the full, un-cropped line on its 80-col screen.
    let os = owner.screen();
    assert_eq!((os.cols, os.rows), (80, 24));
    assert_eq!(os.to_lines()[0], line);

    owner.disconnect();
    viewer.disconnect();
}
