//! Headless tests of the client's mouse-wheel routing. The wheel only drives
//! mosh scrollback when the remote app isn't using the mouse and is on the
//! primary screen; otherwise it must reach the app — forwarded verbatim when the
//! app reads the mouse, or as arrow keys (alternate-scroll) for a plain pager on
//! the alternate screen. Driven over the in-memory transport with a real server
//! emulator + fake PTY, so we can put the server into each mode and watch what
//! lands on its PTY. The prompt→scrollback path is covered in `scroll_client.rs`.

use std::sync::Arc;
use std::time::Duration;

use mish::client::{run_client, ClientInput};
use mish::server::{run_server, PtyControl};
use mish_ssp::clock::{Clock, SystemClock};
use mish_ssp::memory;
use tokio::sync::mpsc;

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// Spawn a server (real emulator + fake PTY) and a client over an in-memory
/// pair. Returns the channels to feed server output, observe PTY input, send
/// client input, and read client frames.
#[allow(clippy::type_complexity)]
fn harness() -> (
    mpsc::Sender<Vec<u8>>,
    mpsc::UnboundedReceiver<PtyControl>,
    mpsc::Sender<ClientInput>,
    mpsc::UnboundedReceiver<Vec<u8>>,
) {
    let (ta, tb) = memory::pair();
    let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());

    let (pty_out_tx, pty_out_rx) = mpsc::channel::<Vec<u8>>(64);
    let (pty_in_tx, pty_in_rx) = mpsc::unbounded_channel::<PtyControl>();
    tokio::spawn(run_server(
        Arc::new(ta),
        mish_terminal::emulator::Emulator::shared(80, 24),
        clock.clone(),
        None,
        pty_out_rx,
        pty_in_tx,
    ));

    let (cin_tx, cin_rx) = mpsc::channel::<ClientInput>(64);
    let (cout_tx, cout_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    tokio::spawn(run_client(
        Arc::new(tb),
        80,
        24,
        clock,
        mish_terminal::predict::PredictMode::Never,
        None,
        cin_rx,
        cout_tx,
    ));

    (pty_out_tx, pty_in_rx, cin_tx, cout_rx)
}

/// Feed `bytes` to the server emulator, then wait until the client has rendered
/// `marker` — proving the screen state those bytes produced (modes included) has
/// synced to the client before we send a mouse event.
async fn sync_state(
    pty_out_tx: &mpsc::Sender<Vec<u8>>,
    cout_rx: &mut mpsc::UnboundedReceiver<Vec<u8>>,
    bytes: &[u8],
    marker: &[u8],
) {
    pty_out_tx.send(bytes.to_vec()).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(frame) = cout_rx.recv().await {
            if contains(&frame, marker) {
                return;
            }
        }
    })
    .await
    .expect("client should render the marker (state synced)");
}

/// Wait for a specific keystroke payload to arrive on the server PTY, skipping
/// the client's initial resize and any unrelated control messages.
async fn expect_pty_input(rx: &mut mpsc::UnboundedReceiver<PtyControl>, want: &[u8]) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(msg) = rx.recv().await {
            if let PtyControl::Input(b) = msg {
                if b == want {
                    return;
                }
            }
        }
        panic!("PTY input channel closed before the expected bytes");
    })
    .await
    .unwrap_or_else(|_| panic!("server PTY never received {want:?}"));
}

/// When the remote app is reading the mouse (e.g. vim with `set mouse=a`), a
/// mouse report is forwarded to it verbatim — not consumed as scrollback.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mouse_forwarded_when_app_reads_mouse() {
    let (pty_out_tx, mut pty_in_rx, cin_tx, mut cout_rx) = harness();

    // App enables SGR mouse reporting, then prints a marker.
    sync_state(&pty_out_tx, &mut cout_rx, b"\x1b[?1000h\x1b[?1006hMOUSEON", b"MOUSEON").await;

    // A left-click report should reach the PTY unchanged.
    let click = b"\x1b[<0;5;5M";
    cin_tx.send(ClientInput::Mouse(click.to_vec())).await.unwrap();
    expect_pty_input(&mut pty_in_rx, click).await;
}

/// A plain pager on the alternate screen (no mouse mode) doesn't read mouse
/// reports — it relies on alternate-scroll. The wheel must reach it as arrow
/// keys, so it scrolls its own content rather than mosh's scrollback.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wheel_becomes_arrows_on_alt_screen() {
    let (pty_out_tx, mut pty_in_rx, cin_tx, mut cout_rx) = harness();

    // Enter the alternate screen and paint a marker there.
    sync_state(&pty_out_tx, &mut cout_rx, b"\x1b[?1049hALTMARK", b"ALTMARK").await;

    // Wheel up (SGR button 64, press) → three up-arrows (no DECCKM ⇒ CSI form).
    cin_tx
        .send(ClientInput::Mouse(b"\x1b[<64;5;5M".to_vec()))
        .await
        .unwrap();
    expect_pty_input(&mut pty_in_rx, b"\x1b[A\x1b[A\x1b[A").await;
}
