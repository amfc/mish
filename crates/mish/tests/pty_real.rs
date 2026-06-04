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
        80,
        24,
        clock.clone(),
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
