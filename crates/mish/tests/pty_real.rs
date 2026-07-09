//! End-to-end test through a *real* PTY child shell (the one piece the loopback
//! test fakes). Spawns `/bin/sh` on a pseudo-terminal, runs the full server and
//! client session loops over the in-memory transport, types a command into the
//! client, and verifies the shell's output comes back and renders on the client.

use std::sync::Arc;
use std::time::Duration;

use mish::client::{run_client, ClientInput};
use mish::pty::PtyProcess;
use mish::server::run_server;
use mish_ssp::clock::{Clock, SystemClock};
use mish_ssp::memory;
use tokio::sync::mpsc;

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_shell_output_reaches_client() {
    let (ta, tb) = memory::pair();
    let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());

    // Real PTY running an interactive shell.
    let pty = PtyProcess::spawn("/bin/sh", 80, 24).expect("spawn shell on PTY");
    tokio::spawn(run_server(
        Arc::new(ta),
        mish_terminal::emulator::Emulator::shared(80, 24),
        clock.clone(),
        None,
        pty.output,
        pty.control,
    ));

    // Client with a channel-faked TTY.
    let (cin_tx, cin_rx) = mpsc::channel::<ClientInput>(64);
    let (cout_tx, mut cout_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    tokio::spawn(run_client(
        Arc::new(tb),
        80,
        24,
        clock.clone(),
        mish_terminal::predict::PredictMode::Never,
        None,
        None, // session name (display-only)
        None,
        cin_rx,
        cout_tx,
    ));

    // Type a command; the shell echoes it and runs it, printing the marker.
    cin_tx
        .send(ClientInput::Keys(b"echo MISH_OK\r".to_vec()))
        .await
        .unwrap();

    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let frame = cout_rx.recv().await.expect("client output");
            if contains(&frame, b"MISH_OK") {
                return;
            }
        }
    })
    .await
    .expect("shell command output should render on the client");
}

/// Port of mosh's pty-deadlock.test: exercising terminal flow control (^S/^Q)
/// around input/output must not wedge the session. We type a command, send
/// XOFF (^S) to pause output, type more, send XON (^Q) to resume, then a final
/// command — and the final marker must still arrive.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn flow_control_does_not_deadlock() {
    let (ta, tb) = memory::pair();
    let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());

    let pty = PtyProcess::spawn("/bin/sh", 80, 24).expect("spawn shell on PTY");
    tokio::spawn(run_server(
        Arc::new(ta),
        mish_terminal::emulator::Emulator::shared(80, 24),
        clock.clone(),
        None,
        pty.output,
        pty.control,
    ));

    let (cin_tx, cin_rx) = mpsc::channel::<ClientInput>(64);
    let (cout_tx, mut cout_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    tokio::spawn(run_client(
        Arc::new(tb),
        80,
        24,
        clock.clone(),
        mish_terminal::predict::PredictMode::Never,
        None,
        None, // session name (display-only)
        None,
        cin_rx,
        cout_tx,
    ));

    // echo, then XOFF, more input while paused, XON, then a final marker.
    for seq in [
        &b"echo AAA\r"[..],
        &b"\x13"[..], // ^S (XOFF)
        &b"echo BBB\r"[..],
        &b"\x11"[..], // ^Q (XON)
        &b"echo DEADLOCK_OK\r"[..],
    ] {
        cin_tx.send(ClientInput::Keys(seq.to_vec())).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let frame = cout_rx.recv().await.expect("client output");
            if contains(&frame, b"DEADLOCK_OK") {
                return;
            }
        }
    })
    .await
    .expect("session must keep flowing through ^S/^Q flow control");
}
