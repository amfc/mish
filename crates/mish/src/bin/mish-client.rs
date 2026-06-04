//! `mish-client`: connect to a `mish-server` over QUIC and attach the local TTY.
//!
//! Captures raw keystrokes and forwards them as a `UserStream`, repaints each
//! received `Screen`, and tracks terminal resizes via SIGWINCH. Detach with
//! `Ctrl-]`.
//!
//! Usage: `mish-client <addr>` (e.g. `mish-client 127.0.0.1:51234`).

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use mish::client::{run_client, ClientInput};
use mish_quic::transport;
use mish_ssp::clock::SystemClock;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};

/// Detach key: Ctrl-] (0x1d), same as telnet's escape.
const DETACH: u8 = 0x1d;

/// Restores cooked mode and leaves the alternate screen on drop.
struct TerminalGuard;
impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = crossterm::terminal::disable_raw_mode();
        // Leave alternate screen, show cursor.
        print!("\x1b[?1049l\x1b[?25h");
        use std::io::Write;
        let _ = std::io::stdout().flush();
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let addr: SocketAddr = std::env::args()
        .nth(1)
        .context("usage: mish-client <addr>")?
        .parse()
        .context("parsing server address")?;

    let endpoint = transport::loopback_client().context("creating QUIC client endpoint")?;
    let t = transport::connect(&endpoint, addr, "localhost")
        .await
        .context("connecting to server")?;

    let (cols, rows) = crossterm::terminal::size().unwrap_or((80, 24));

    crossterm::terminal::enable_raw_mode().context("entering raw mode")?;
    // Enter alternate screen so we don't clobber the user's scrollback.
    print!("\x1b[?1049h");
    use std::io::Write;
    std::io::stdout().flush().ok();
    let _guard = TerminalGuard;

    let (in_tx, in_rx) = mpsc::channel::<ClientInput>(256);
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let (detach_tx, detach_rx) = oneshot::channel::<()>();

    // stdout: write rendered frames.
    let writer = tokio::spawn(async move {
        let mut stdout = tokio::io::stdout();
        while let Some(bytes) = out_rx.recv().await {
            if stdout.write_all(&bytes).await.is_err() || stdout.flush().await.is_err() {
                break;
            }
        }
    });

    // stdin: forward raw keystrokes; Ctrl-] detaches.
    let key_tx = in_tx.clone();
    tokio::spawn(async move {
        let mut stdin = tokio::io::stdin();
        let mut buf = [0u8; 1024];
        let mut detach = Some(detach_tx);
        loop {
            match stdin.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if buf[..n].contains(&DETACH) {
                        if let Some(tx) = detach.take() {
                            let _ = tx.send(());
                        }
                        break;
                    }
                    if key_tx.send(ClientInput::Keys(buf[..n].to_vec())).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    // SIGWINCH: report new terminal size.
    let resize_tx = in_tx.clone();
    tokio::spawn(async move {
        let mut sig = match tokio::signal::unix::signal(
            tokio::signal::unix::SignalKind::window_change(),
        ) {
            Ok(s) => s,
            Err(_) => return,
        };
        while sig.recv().await.is_some() {
            if let Ok((cols, rows)) = crossterm::terminal::size() {
                if resize_tx.send(ClientInput::Resize { cols, rows }).await.is_err() {
                    break;
                }
            }
        }
    });

    let clock = Arc::new(SystemClock::new());

    // Run until the session ends or the user detaches. Predictive echo is
    // adaptive (mosh's default --predict=adaptive): predictions show once the
    // link is laggy enough to benefit.
    tokio::select! {
        _ = run_client(
            Arc::new(t),
            cols,
            rows,
            clock,
            mish_terminal::predict::PredictMode::Adaptive,
            in_rx,
            out_tx,
        ) => {}
        _ = detach_rx => {}
    }

    drop(_guard);
    writer.abort();
    Ok(())
}
